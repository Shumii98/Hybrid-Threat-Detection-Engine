# Hybrid Threat Detection Engine

A defensive cybersecurity threat detection engine built with FastAPI, PostgreSQL, SQLAlchemy, and rule-based security analytics.

The project processes normalized security events, applies detection rules, calculates explainable risk scores, and generates persistent security alerts.

## Overview

The Hybrid Threat Detection Engine is designed as an extensible Security Operations Center (SOC) detection backend.

The MVP currently focuses on explainable rule-based detection. The architecture is designed to support future behavioral analytics and machine learning models without replacing the existing deterministic detection layer.

## Key Features

* Normalized security event ingestion
* PostgreSQL persistence
* SQLAlchemy ORM
* FastAPI REST API
* Brute-force detection
* Password-spraying detection
* Detection rule registry
* Explainable risk scoring
* Persistent security alerts
* Alert status tracking
* Automatic event-field normalization
* Database migrations with Alembic
* Dockerized PostgreSQL
* Automated test suite
* API documentation through Swagger UI

## Detection Capabilities

### Brute-Force Detection

Detects repeated failed authentication attempts originating from the same source IP.

Default threshold:

```text
5 failed login attempts
```

Example detection:

```text
Rule: BRUTE_FORCE_DETECTION
Severity: High
Risk Score: 60
```

### Password-Spray Detection

Detects authentication failures against multiple usernames from the same source IP.

Default threshold:

```text
3 unique usernames
```

Example detection:

```text
Rule: PASSWORD_SPRAY_DETECTION
Severity: High
Risk Score: 60
```

## Risk Scoring

The engine uses an explainable risk-scoring model based on detection severity and activity above the configured threshold.

| Severity | Base Score |
| -------- | ---------- |
| Low      | 10         |
| Medium   | 30         |
| High     | 60         |
| Critical | 80         |

Additional failed attempts can increase the score, with the final score capped at 100.

This provides a simple and transparent prioritization mechanism for SOC analysts.

## Architecture

```text
Security Event
      |
      v
Event Normalizer
      |
      v
PostgreSQL
      |
      v
Detection Engine
      |
      +--------------------+
      |                    |
      v                    v
Brute-Force Rule      Password-Spray Rule
      |                    |
      +---------+----------+
                |
                v
          Risk Scorer
                |
                v
         Detection Result
                |
                v
          Alert Service
                |
                v
        Persistent Alert
```

## Project Structure

```text
Hybrid-Threat-Detection-Engine/
│
├── alembic/
│   ├── versions/
│   └── env.py
│
├── app/
│   ├── api/
│   │   └── detections.py
│   │
│   ├── core/
│   │   ├── config.py
│   │   └── database.py
│   │
│   ├── models/
│   │   ├── alert.py
│   │   └── security_event.py
│   │
│   ├── schemas/
│   │   ├── detection.py
│   │   └── security_event.py
│   │
│   ├── services/
│   │   ├── alert_service.py
│   │   ├── detection_engine.py
│   │   ├── event_normalizer.py
│   │   ├── risk_scorer.py
│   │   ├── rule_registry.py
│   │   └── security_event_service.py
│   │
│   └── main.py
│
├── tests/
│   ├── test_alert_service.py
│   ├── test_api.py
│   ├── test_detections.py
│   ├── test_end_to_end.py
│   ├── test_risk_scorer.py
│   └── test_security_event_service.py
│
├── .env.example
├── .gitignore
├── alembic.ini
├── docker-compose.yml
├── requirements.txt
└── README.md
```

## Technology Stack

| Technology    | Purpose                 |
| ------------- | ----------------------- |
| Python 3.12   | Application development |
| FastAPI       | REST API                |
| Pydantic      | Data validation         |
| SQLAlchemy    | Database ORM            |
| PostgreSQL 16 | Persistent storage      |
| Alembic       | Database migrations     |
| Docker        | PostgreSQL environment  |
| Pytest        | Automated testing       |

## API Endpoints

### Brute-Force Detection

```http
GET /detections/brute-force/{source_ip}
```

Runs the brute-force detection rule against a source IP.

### Password-Spray Detection

```http
GET /detections/password-spray/{source_ip}
```

Runs the password-spray detection rule against a source IP.

### Run Registered Rule

```http
GET /detections/run/{rule_name}/{source_ip}
```

Executes a detection rule through the rule registry.

Example:

```text
/detections/run/brute_force/192.168.1.100
```

### Create Brute-Force Alert

```http
POST /detections/brute-force/{source_ip}/alert
```

Runs the brute-force rule and persists an alert when malicious activity is detected.

### Create Password-Spray Alert

```http
POST /detections/password-spray/{source_ip}/alert
```

Runs the password-spray rule and persists an alert when malicious activity is detected.

## Running the Project

### 1. Clone the Repository

```bash
git clone https://github.com/Shumii98/Hybrid-Threat-Detection-Engine.git
cd Hybrid-Threat-Detection-Engine
```

### 2. Create a Virtual Environment

Windows PowerShell:

```powershell
python -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell execution policy blocks activation:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

### 3. Install Dependencies

```powershell
python -m pip install -r requirements.txt
```

### 4. Configure Environment Variables

Create a `.env` file from `.env.example`.

Configure the PostgreSQL connection for the Docker database.

The `.env` file is intentionally excluded from Git.

### 5. Start PostgreSQL

```powershell
docker compose up -d
```

Check the container:

```powershell
docker compose ps
```

The PostgreSQL service is exposed on:

```text
localhost:5433
```

### 6. Run Database Migrations

```powershell
alembic upgrade head
```

### 7. Start FastAPI

```powershell
uvicorn app.main:app --reload
```

API:

```text
http://127.0.0.1:8000
```

Swagger documentation:

```text
http://127.0.0.1:8000/docs
```

## Testing

The project includes unit, API, service, risk-scoring, and end-to-end workflow tests.

Run:

```powershell
python -m pytest -q
```

Current result:

```text
67 passed
```

The test suite verifies:

* Detection rules
* Detection thresholds
* Password-spray username counting
* Rule registry behavior
* Risk scoring
* Alert creation
* Non-detection behavior
* Event normalization
* Security event persistence
* API endpoints
* End-to-end detection-to-alert workflow

## Example Detection Workflow

A typical brute-force workflow is:

```text
Failed Authentication Events
            |
            v
    Event Normalization
            |
            v
       PostgreSQL
            |
            v
    Brute-Force Rule
            |
            v
      Risk Scoring
            |
            v
    Detection Result
            |
            v
      Alert Service
            |
            v
     Security Alert
```

## Security Engineering Concepts Demonstrated

This project demonstrates practical defensive security engineering concepts including:

* Security event normalization
* Detection engineering
* Rule-based threat detection
* Authentication attack detection
* Risk-based alert prioritization
* SOC alert generation
* Database-backed security telemetry
* API-based security automation
* Test-driven validation
* Containerized infrastructure
* Extensible detection architecture

## Future Enhancements

The MVP establishes the deterministic detection foundation for future development.

Planned enhancements include:

* Sigma-compatible detection rules
* Additional authentication and network detections
* Detection deduplication
* Event correlation
* Time-window based detection
* Alert lifecycle management
* MITRE ATT&CK technique mapping
* Behavioral baselines
* Isolation Forest anomaly detection
* Local Outlier Factor anomaly detection
* Hybrid rule + ML scoring
* React-based SOC dashboard
* Real-time event ingestion
* Detection performance metrics

## Project Status

**MVP Complete**

The current release provides a functional backend for normalized security events, rule-based detection, explainable risk scoring, and persistent security alerts.

The architecture is intentionally designed to evolve toward a hybrid detection platform combining deterministic security rules with behavioral and machine-learning based analytics.
