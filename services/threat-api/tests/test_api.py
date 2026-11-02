from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health():
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"


def test_high_risk():
    result = client.post(
        "/api/v1/analyze",
        json={"text": "Congratulations winner! Urgent: send your MTN mobile money PIN to claim prize"},
    )
    assert result.status_code == 200
    data = result.json()
    assert data["risk_level"] == "high"
    assert data["category_scores"]["credential_harvesting"] >= 35


def test_benign_not_certified_safe():
    data = client.post("/api/v1/analyze", json={"text": "Hello, are you available tomorrow?"}).json()
    assert data["risk_score"] == 0
    assert "does not establish safety" in data["recommendation"]


def test_empty_rejected():
    assert client.post("/api/v1/analyze", json={"text": ""}).status_code == 422


def test_oversized_body_rejected():
    assert (
        client.post(
            "/api/v1/analyze",
            content=b"x" * 17000,
            headers={"content-type": "application/json"},
        ).status_code
        == 413
    )


def test_ussd_diversion_and_mobile_money_reversal():
    res = client.post(
        "/api/v1/analyze",
        json={"text": "Urgent: I wrongly sent UGX 250,000 by mistake. Dial *21*0772112233# to reverse the money."},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["risk_level"] == "high"
    assert any(u["pattern_type"] == "call_or_sms_diversion_ussd" for u in body["ussd_inspections"])
    assert any("##002#" in s for s in body["safe_next_steps"])


def test_brand_lookalike_vs_official_domain():
    phish = client.post(
        "/api/v1/analyze",
        json={"text": "Verify at https://stanbic-uganda-verify.top/login?redirect=home"},
    ).json()
    assert phish["url_inspections"][0]["impersonated_brand"] == "STANBIC"
    assert phish["url_inspections"][0]["suspicious_tld"] is True

    official = client.post(
        "/api/v1/analyze",
        json={"text": "Visit https://www.stanbicbank.co.ug/personal"},
    ).json()
    assert official["url_inspections"][0]["impersonated_brand"] is None
    assert official["risk_score"] == 0


def test_incident_report_redacts_pii_and_secrets():
    res = client.post(
        "/api/v1/incident-report",
        json={
            "text": "Call +256772998877 or email fraud@example.org with PIN 4912 or visit https://mtn-claim.xyz/a?token=sk-secret999888777"
        },
    )
    assert res.status_code == 200
    body = res.json()
    assert "256772998877" not in body["redacted_input"]
    assert "4912" not in body["redacted_input"]
    assert "fraud@example.org" not in body["redacted_input"]
    assert "sk-secret999888777" not in body["redacted_input"]
    assert body["redaction_counts"]["phones_detected"] >= 1


def test_batch_analysis():
    res = client.post(
        "/api/v1/analyze/batch",
        json={
            "items": [
                "URGENT! Send your OTP to unlock your account.",
                "Lunch meeting at 1pm tomorrow.",
            ]
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["count"] == 2
    assert data["results"][0]["risk_level"] in ("elevated", "high")
    assert data["results"][1]["risk_score"] == 0
