from datetime import datetime, timezone

from app.services.security_event_service import create_security_event


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
        obj.id = 200


def make_event_data(
    source="authentication",
    event_type="login_failed",
    source_ip="192.168.1.100",
    username="admin",
    severity="low",
    raw_message="Failed login attempt.",
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


def test_create_security_event_returns_event():
    db = FakeDB()

    from app.schemas.security_event import SecurityEventCreate

    event_data = SecurityEventCreate(
        **make_event_data()
    )

    event = create_security_event(
        db=db,
        event_data=event_data,
    )

    assert event is not None
    assert event.id == 200


def test_create_security_event_sets_source():
    db = FakeDB()

    from app.schemas.security_event import SecurityEventCreate

    event_data = SecurityEventCreate(
        **make_event_data(source="authentication")
    )

    event = create_security_event(
        db=db,
        event_data=event_data,
    )

    assert event.source == "authentication"


def test_create_security_event_sets_event_type():
    db = FakeDB()

    from app.schemas.security_event import SecurityEventCreate

    event_data = SecurityEventCreate(
        **make_event_data(event_type="login_failed")
    )

    event = create_security_event(
        db=db,
        event_data=event_data,
    )

    assert event.event_type == "login_failed"


def test_create_security_event_sets_source_ip():
    db = FakeDB()

    from app.schemas.security_event import SecurityEventCreate

    event_data = SecurityEventCreate(
        **make_event_data(source_ip="10.10.10.25")
    )

    event = create_security_event(
        db=db,
        event_data=event_data,
    )

    assert event.source_ip == "10.10.10.25"


def test_create_security_event_sets_username():
    db = FakeDB()

    from app.schemas.security_event import SecurityEventCreate

    event_data = SecurityEventCreate(
        **make_event_data(username="alice")
    )

    event = create_security_event(
        db=db,
        event_data=event_data,
    )

    assert event.username == "alice"


def test_create_security_event_sets_severity():
    db = FakeDB()

    from app.schemas.security_event import SecurityEventCreate

    event_data = SecurityEventCreate(
        **make_event_data(severity="high")
    )

    event = create_security_event(
        db=db,
        event_data=event_data,
    )

    assert event.severity == "high"


def test_create_security_event_sets_raw_message():
    db = FakeDB()

    from app.schemas.security_event import SecurityEventCreate

    event_data = SecurityEventCreate(
        **make_event_data(
            raw_message="Multiple failed login attempts detected."
        )
    )

    event = create_security_event(
        db=db,
        event_data=event_data,
    )

    assert event.raw_message == (
        "Multiple failed login attempts detected."
    )


def test_create_security_event_adds_to_database():
    db = FakeDB()

    from app.schemas.security_event import SecurityEventCreate

    event_data = SecurityEventCreate(
        **make_event_data()
    )

    create_security_event(
        db=db,
        event_data=event_data,
    )

    assert db.added is not None
    assert db.added.source == "authentication"


def test_create_security_event_commits_database():
    db = FakeDB()

    from app.schemas.security_event import SecurityEventCreate

    event_data = SecurityEventCreate(
        **make_event_data()
    )

    create_security_event(
        db=db,
        event_data=event_data,
    )

    assert db.committed is True


def test_create_security_event_refreshes_database_object():
    db = FakeDB()

    from app.schemas.security_event import SecurityEventCreate

    event_data = SecurityEventCreate(
        **make_event_data()
    )

    event = create_security_event(
        db=db,
        event_data=event_data,
    )

    assert db.refreshed is True
    assert event.id == 200