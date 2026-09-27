from datetime import datetime, timezone
from types import SimpleNamespace

from app.services.alert_service import create_alert
from app.services.detection_engine import (
    detect_brute_force,
    detect_password_spray,
)
from app.services.security_event_service import create_security_event


class FakeQuery:
    def __init__(self, events):
        self.events = events

    def filter(self, *args):
        return self

    def all(self):
        return self.events


class FakeDB:
    def __init__(self, events=None):
        self.events = events or []
        self.added = None
        self.committed = False
        self.refreshed = False

    def query(self, model):
        return FakeQuery(self.events)

    def add(self, obj):
        self.added = obj

        if hasattr(obj, "source") and hasattr(obj, "event_type"):
            self.events.append(obj)

    def commit(self):
        self.committed = True

    def refresh(self, obj):
        self.refreshed = True

        if getattr(obj, "id", None) is None:
            obj.id = 500


def make_event_data(
    source="Authentication",
    event_type="LOGIN_FAILED",
    source_ip=" 192.168.1.100 ",
    username=" admin ",
    severity=" HIGH ",
    raw_message=" Failed login attempt. ",
):
    return {
        "timestamp": datetime.now(timezone.utc),
        "source": source,
        "event_type": event_type,
        "source_ip": source_ip,
        "destination_ip": None,
        "username": username,
        "severity": severity,
        "raw_message": raw_message,
    }


def make_detection(
    detected=True,
    rule="BRUTE_FORCE_DETECTION",
    severity="high",
    risk_score=60,
    source_ip="192.168.1.100",
    message="Detected brute-force activity.",
    failed_attempts=5,
    threshold=5,
):
    return SimpleNamespace(
        detected=detected,
        rule=rule,
        severity=severity,
        risk_score=risk_score,
        source_ip=source_ip,
        message=message,
        failed_attempts=failed_attempts,
        threshold=threshold,
    )


def test_event_normalization_and_persistence():
    db = FakeDB()

    from app.schemas.security_event import SecurityEventCreate

    event_data = SecurityEventCreate(
        **make_event_data()
    )

    event = create_security_event(
        db=db,
        event_data=event_data,
    )

    assert event.source == "authentication"
    assert event.event_type == "login_failed"
    assert event.source_ip == "192.168.1.100"
    assert event.username == "admin"
    assert event.severity == "high"
    assert event.raw_message == "Failed login attempt."
    assert db.committed is True
    assert db.refreshed is True


def test_multiple_failed_events_trigger_brute_force():
    events = [
        SimpleNamespace(
            source="authentication",
            event_type="login_failed",
            source_ip="192.168.1.100",
            username="admin",
        )
        for _ in range(5)
    ]

    db = FakeDB(events)

    result = detect_brute_force(
        db=db,
        source_ip="192.168.1.100",
    )

    assert result.detected is True
    assert result.rule == "BRUTE_FORCE_DETECTION"
    assert result.failed_attempts == 5
    assert result.risk_score == 60


def test_multiple_usernames_trigger_password_spray():
    events = [
        SimpleNamespace(
            source="authentication",
            event_type="login_failed",
            source_ip="192.168.1.100",
            username=username,
        )
        for username in ["alice", "bob", "charlie"]
    ]

    db = FakeDB(events)

    result = detect_password_spray(
        db=db,
        source_ip="192.168.1.100",
    )

    assert result.detected is True
    assert result.rule == "PASSWORD_SPRAY_DETECTION"
    assert result.failed_attempts == 3
    assert result.risk_score == 60


def test_detection_creates_alert():
    db = FakeDB()

    detection = make_detection()

    alert = create_alert(
        db=db,
        detection=detection,
    )

    assert alert is not None
    assert alert.rule == "BRUTE_FORCE_DETECTION"
    assert alert.severity == "high"
    assert alert.risk_score == 60
    assert alert.source_ip == "192.168.1.100"
    assert alert.status == "open"


def test_non_detection_does_not_create_alert():
    db = FakeDB()

    detection = make_detection(
        detected=False,
        risk_score=0,
    )

    alert = create_alert(
        db=db,
        detection=detection,
    )

    assert alert is None
    assert db.added is None
    assert db.committed is False


def test_full_brute_force_detection_to_alert_workflow():
    events = [
        SimpleNamespace(
            source="authentication",
            event_type="login_failed",
            source_ip="192.168.1.100",
            username="admin",
        )
        for _ in range(5)
    ]

    db = FakeDB(events)

    detection = detect_brute_force(
        db=db,
        source_ip="192.168.1.100",
    )

    assert detection.detected is True
    assert detection.risk_score == 60

    alert = create_alert(
        db=db,
        detection=detection,
    )

    assert alert is not None
    assert alert.rule == "BRUTE_FORCE_DETECTION"
    assert alert.risk_score == detection.risk_score
    assert alert.source_ip == detection.source_ip
    assert alert.status == "open"