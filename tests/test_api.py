from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_docs_endpoint():
    response = client.get("/docs")

    assert response.status_code == 200


def test_brute_force_endpoint():
    response = client.get(
        "/detections/brute-force/192.168.1.100"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["rule"] == "BRUTE_FORCE_DETECTION"
    assert data["source_ip"] == "192.168.1.100"
    assert "detected" in data
    assert "failed_attempts" in data
    assert "threshold" in data
    assert "risk_score" in data


def test_password_spray_endpoint():
    response = client.get(
        "/detections/password-spray/192.168.1.100"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["rule"] == "PASSWORD_SPRAY_DETECTION"
    assert data["source_ip"] == "192.168.1.100"
    assert "detected" in data
    assert "failed_attempts" in data
    assert "threshold" in data
    assert "risk_score" in data


def test_rule_registry_brute_force_endpoint():
    response = client.get(
        "/detections/run/brute_force/192.168.1.100"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["rule"] == "BRUTE_FORCE_DETECTION"


def test_rule_registry_password_spray_endpoint():
    response = client.get(
        "/detections/run/password_spray/192.168.1.100"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["rule"] == "PASSWORD_SPRAY_DETECTION"


def test_unknown_rule_endpoint():
    response = client.get(
        "/detections/run/unknown_rule/192.168.1.100"
    )

    assert response.status_code == 404

    data = response.json()

    assert data["detail"] == "Unknown detection rule: unknown_rule"


def test_brute_force_alert_endpoint():
    response = client.post(
        "/detections/brute-force/192.168.1.100/alert"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["rule"] == "BRUTE_FORCE_DETECTION"
    assert data["source_ip"] == "192.168.1.100"
    assert "alert_id" in data
    assert "alert_status" in data
    assert "created_at" in data


def test_password_spray_alert_endpoint():
    response = client.post(
        "/detections/password-spray/192.168.1.100/alert"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["rule"] == "PASSWORD_SPRAY_DETECTION"
    assert data["source_ip"] == "192.168.1.100"
    assert "alert_id" in data
    assert "alert_status" in data
    assert "created_at" in data