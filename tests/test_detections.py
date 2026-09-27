from types import SimpleNamespace

from app.services.detection_engine import (
    detect_brute_force,
    detect_password_spray,
)
from app.services.rule_registry import run_rule


class FakeQuery:
    def __init__(self, events):
        self.events = events

    def filter(self, *args):
        return self

    def all(self):
        return self.events


class FakeDB:
    def __init__(self, events):
        self.events = events

    def query(self, model):
        return FakeQuery(self.events)


def make_event(
    source_ip="192.168.1.100",
    username="admin",
):
    return SimpleNamespace(
        source="authentication",
        event_type="login_failed",
        source_ip=source_ip,
        username=username,
    )


# =========================================================
# BRUTE-FORCE DETECTION TESTS
# =========================================================

def test_brute_force_detected():
    events = [make_event() for _ in range(5)]
    db = FakeDB(events)

    result = detect_brute_force(
        db=db,
        source_ip="192.168.1.100",
    )

    assert result.detected is True
    assert result.failed_attempts == 5
    assert result.threshold == 5
    assert result.rule == "BRUTE_FORCE_DETECTION"
    assert result.severity == "high"
    assert result.risk_score > 0


def test_brute_force_not_detected():
    events = [make_event() for _ in range(2)]
    db = FakeDB(events)

    result = detect_brute_force(
        db=db,
        source_ip="192.168.1.100",
    )

    assert result.detected is False
    assert result.failed_attempts == 2
    assert result.threshold == 5
    assert result.rule == "BRUTE_FORCE_DETECTION"
    assert result.severity == "medium"


def test_brute_force_exact_threshold():
    events = [make_event() for _ in range(5)]
    db = FakeDB(events)

    result = detect_brute_force(
        db=db,
        source_ip="192.168.1.100",
        threshold=5,
    )

    assert result.detected is True
    assert result.failed_attempts == result.threshold


def test_brute_force_custom_threshold():
    events = [make_event() for _ in range(3)]
    db = FakeDB(events)

    result = detect_brute_force(
        db=db,
        source_ip="192.168.1.100",
        threshold=3,
    )

    assert result.detected is True
    assert result.failed_attempts == 3
    assert result.threshold == 3


def test_brute_force_zero_events():
    db = FakeDB([])

    result = detect_brute_force(
        db=db,
        source_ip="192.168.1.100",
    )

    assert result.detected is False
    assert result.failed_attempts == 0
    assert result.threshold == 5
    assert result.risk_score == 0


def test_brute_force_one_attempt():
    db = FakeDB([make_event()])

    result = detect_brute_force(
        db=db,
        source_ip="192.168.1.100",
    )

    assert result.detected is False
    assert result.failed_attempts == 1


def test_brute_force_four_attempts():
    events = [make_event() for _ in range(4)]
    db = FakeDB(events)

    result = detect_brute_force(
        db=db,
        source_ip="192.168.1.100",
    )

    assert result.detected is False
    assert result.failed_attempts == 4
    assert result.threshold == 5


def test_brute_force_six_attempts():
    events = [make_event() for _ in range(6)]
    db = FakeDB(events)

    result = detect_brute_force(
        db=db,
        source_ip="192.168.1.100",
    )

    assert result.detected is True
    assert result.failed_attempts == 6
    assert result.severity == "high"


def test_brute_force_custom_threshold_two():
    events = [make_event(), make_event()]
    db = FakeDB(events)

    result = detect_brute_force(
        db=db,
        source_ip="192.168.1.100",
        threshold=2,
    )

    assert result.detected is True
    assert result.failed_attempts == 2
    assert result.threshold == 2


def test_brute_force_custom_threshold_ten():
    events = [make_event() for _ in range(5)]
    db = FakeDB(events)

    result = detect_brute_force(
        db=db,
        source_ip="192.168.1.100",
        threshold=10,
    )

    assert result.detected is False
    assert result.failed_attempts == 5
    assert result.threshold == 10


def test_brute_force_message_when_detected():
    events = [make_event() for _ in range(5)]
    db = FakeDB(events)

    result = detect_brute_force(
        db=db,
        source_ip="192.168.1.100",
    )

    assert "Detected 5 failed login attempts" in result.message
    assert "192.168.1.100" in result.message


def test_brute_force_message_when_not_detected():
    db = FakeDB([make_event()])

    result = detect_brute_force(
        db=db,
        source_ip="192.168.1.100",
    )

    assert "No brute-force activity detected" in result.message


# =========================================================
# PASSWORD-SPRAY DETECTION TESTS
# =========================================================

def test_password_spray_detected():
    events = [
        make_event(username="alice"),
        make_event(username="bob"),
        make_event(username="charlie"),
    ]

    db = FakeDB(events)

    result = detect_password_spray(
        db=db,
        source_ip="192.168.1.100",
    )

    assert result.detected is True
    assert result.failed_attempts == 3
    assert result.threshold == 3
    assert result.rule == "PASSWORD_SPRAY_DETECTION"
    assert result.severity == "high"
    assert result.risk_score > 0


def test_password_spray_not_detected():
    events = [
        make_event(username="alice"),
        make_event(username="bob"),
    ]

    db = FakeDB(events)

    result = detect_password_spray(
        db=db,
        source_ip="192.168.1.100",
    )

    assert result.detected is False
    assert result.failed_attempts == 2
    assert result.threshold == 3
    assert result.rule == "PASSWORD_SPRAY_DETECTION"
    assert result.severity == "medium"


def test_password_spray_exact_threshold():
    events = [
        make_event(username="alice"),
        make_event(username="bob"),
        make_event(username="charlie"),
    ]

    db = FakeDB(events)

    result = detect_password_spray(
        db=db,
        source_ip="192.168.1.100",
        threshold=3,
    )

    assert result.detected is True
    assert result.failed_attempts == 3
    assert result.failed_attempts == result.threshold


def test_password_spray_duplicate_username():
    events = [
        make_event(username="alice"),
        make_event(username="alice"),
        make_event(username="bob"),
    ]

    db = FakeDB(events)

    result = detect_password_spray(
        db=db,
        source_ip="192.168.1.100",
    )

    assert result.detected is False
    assert result.failed_attempts == 2


def test_password_spray_all_duplicate_users():
    events = [
        make_event(username="alice"),
        make_event(username="alice"),
        make_event(username="alice"),
        make_event(username="alice"),
    ]

    db = FakeDB(events)

    result = detect_password_spray(
        db=db,
        source_ip="192.168.1.100",
    )

    assert result.detected is False
    assert result.failed_attempts == 1


def test_password_spray_empty_events():
    db = FakeDB([])

    result = detect_password_spray(
        db=db,
        source_ip="192.168.1.100",
    )

    assert result.detected is False
    assert result.failed_attempts == 0
    assert result.threshold == 3
    assert result.risk_score == 0


def test_password_spray_single_username():
    db = FakeDB([
        make_event(username="alice"),
    ])

    result = detect_password_spray(
        db=db,
        source_ip="192.168.1.100",
    )

    assert result.detected is False
    assert result.failed_attempts == 1


def test_password_spray_custom_threshold_two():
    events = [
        make_event(username="alice"),
        make_event(username="bob"),
    ]

    db = FakeDB(events)

    result = detect_password_spray(
        db=db,
        source_ip="192.168.1.100",
        threshold=2,
    )

    assert result.detected is True
    assert result.failed_attempts == 2
    assert result.threshold == 2


def test_password_spray_custom_threshold_four():
    events = [
        make_event(username="alice"),
        make_event(username="bob"),
        make_event(username="charlie"),
    ]

    db = FakeDB(events)

    result = detect_password_spray(
        db=db,
        source_ip="192.168.1.100",
        threshold=4,
    )

    assert result.detected is False
    assert result.failed_attempts == 3
    assert result.threshold == 4


def test_password_spray_none_usernames_ignored():
    events = [
        make_event(username=None),
        make_event(username="alice"),
        make_event(username="bob"),
    ]

    db = FakeDB(events)

    result = detect_password_spray(
        db=db,
        source_ip="192.168.1.100",
    )

    assert result.failed_attempts == 2
    assert result.detected is False


# =========================================================
# RULE REGISTRY TESTS
# =========================================================

def test_rule_registry_brute_force():
    events = [make_event() for _ in range(5)]
    db = FakeDB(events)

    result = run_rule(
        db=db,
        rule_name="brute_force",
        source_ip="192.168.1.100",
    )

    assert result.detected is True
    assert result.rule == "BRUTE_FORCE_DETECTION"


def test_rule_registry_password_spray():
    events = [
        make_event(username="alice"),
        make_event(username="bob"),
        make_event(username="charlie"),
    ]

    db = FakeDB(events)

    result = run_rule(
        db=db,
        rule_name="password_spray",
        source_ip="192.168.1.100",
    )

    assert result.detected is True
    assert result.rule == "PASSWORD_SPRAY_DETECTION"


def test_rule_registry_unknown_rule():
    db = FakeDB([])

    try:
        run_rule(
            db=db,
            rule_name="unknown_rule",
            source_ip="192.168.1.100",
        )
        assert False, "Expected ValueError for unknown rule"
    except ValueError as exc:
        assert str(exc) == "Unknown detection rule: unknown_rule"