from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health():
    assert client.get("/health").json()["status"] == "ok"

def test_high_risk():
    result = client.post("/api/v1/analyze", json={"text": "Congratulations winner! Urgent: send your MTN mobile money PIN to claim prize"})
    assert result.status_code == 200
    assert result.json()["risk_level"] == "high"

def test_benign_not_certified_safe():
    data = client.post("/api/v1/analyze", json={"text": "Hello, are you available tomorrow?"}).json()
    assert data["risk_score"] == 0
    assert "does not establish safety" in data["recommendation"]

def test_empty_rejected():
    assert client.post("/api/v1/analyze", json={"text": ""}).status_code == 422

def test_oversized_body_rejected():
    assert client.post("/api/v1/analyze", content=b"x" * 17000, headers={"content-type": "application/json"}).status_code == 413
