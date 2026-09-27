from types import SimpleNamespace

from app.services.alert_service import create_alert


class FakeDB:
    def __init__(self):
        self.added = None
        self.committed = False
        self.refreshed = False

    def add(self, obj):
        self.added = obj

    def commit(self):
        self.committed = True

    def refresh(self, obj):
        self.refreshed = True
        obj.id = 100


def make_detection(
    detected=True,
    rule="BRUTE_FORCE_DETECTION",
    severity="high",
    risk_score=60,
    source_ip="192.168.1.100",
    message="Detected brute-force activity.",
):
    return SimpleNamespace(
        detected=detected,
        rule=rule,
        severity=severity,
        risk_score=risk_score,
        source_ip=source_ip,
        message=message,
    )


def test_create_alert_when_detection_is_triggered():
    db = FakeDB()
    detection = make_detection()

    alert = create_alert(
        db=db,
        detection=detection,
    )

    assert alert is not None
    assert alert.id == 100
    assert alert.rule == "BRUTE_FORCE_DETECTION"
    assert alert.severity == "high"
    assert alert.risk_score == 60
    assert alert.source_ip == "192.168.1.100"
    assert alert.message == "Detected brute-force activity."
    assert alert.status == "open"


def test_create_alert_adds_alert_to_database():
    db = FakeDB()
    detection = make_detection()

    create_alert(
        db=db,
        detection=detection,
    )

    assert db.added is not None
    assert db.added.rule == "BRUTE_FORCE_DETECTION"


def test_create_alert_commits_transaction():
    db = FakeDB()
    detection = make_detection()

    create_alert(
        db=db,
        detection=detection,
    )

    assert db.committed is True


def test_create_alert_refreshes_alert():
    db = FakeDB()
    detection = make_detection()

    alert = create_alert(
        db=db,
        detection=detection,
    )

    assert db.refreshed is True
    assert alert.id == 100


def test_create_alert_returns_none_when_not_detected():
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
    assert db.refreshed is False


def test_create_alert_preserves_password_spray_rule():
    db = FakeDB()

    detection = make_detection(
        rule="PASSWORD_SPRAY_DETECTION",
        severity="high",
        risk_score=70,
        message="Password spraying detected against 3 accounts.",
    )

    alert = create_alert(
        db=db,
        detection=detection,
    )

    assert alert.rule == "PASSWORD_SPRAY_DETECTION"
    assert alert.severity == "high"
    assert alert.risk_score == 70
    assert alert.message == "Password spraying detected against 3 accounts."


def test_create_alert_preserves_source_ip():
    db = FakeDB()

    detection = make_detection(
        source_ip="10.10.10.25",
    )

    alert = create_alert(
        db=db,
        detection=detection,
    )

    assert alert.source_ip == "10.10.10.25"


def test_create_alert_uses_default_severity():
    db = FakeDB()

    detection = make_detection(
        severity=None,
    )

    alert = create_alert(
        db=db,
        detection=detection,
    )

    assert alert.severity == "medium"


def test_create_alert_uses_default_message():
    db = FakeDB()

    detection = make_detection(
        message=None,
    )

    alert = create_alert(
        db=db,
        detection=detection,
    )

    assert alert.message == "Security detection triggered."


def test_create_alert_status_is_open():
    db = FakeDB()
    detection = make_detection()

    alert = create_alert(
        db=db,
        detection=detection,
    )

    assert alert.status == "open"