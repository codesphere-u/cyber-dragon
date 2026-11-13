import uuid

from fastapi.testclient import TestClient

from app import main as threat_main
from app.main import app

client = TestClient(app)

EXPECTED_SECURITY_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "cache-control": "no-store",
}


def _assert_security_headers(res):
    for name, expected in EXPECTED_SECURITY_HEADERS.items():
        assert res.headers.get(name) == expected
    req_id = res.headers.get("x-request-id")
    assert req_id is not None and len(req_id) > 0


def test_health():
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"
    _assert_security_headers(res)


def test_health_head_and_k8s_probes():
    head_res = client.head("/health")
    assert head_res.status_code == 200
    assert head_res.text == ""
    _assert_security_headers(head_res)

    for path, expected_status in (("/healthz", "ok"), ("/readyz", "ready")):
        get_res = client.get(path)
        assert get_res.status_code == 200
        assert get_res.json()["status"] == expected_status
        _assert_security_headers(get_res)

        probe_head = client.head(path)
        assert probe_head.status_code == 200
        _assert_security_headers(probe_head)


def test_request_id_propagation_and_sanitization():
    custom_id = "trace-req_123.abc"
    res = client.get("/health", headers={"X-Request-ID": custom_id})
    assert res.status_code == 200
    assert res.headers.get("x-request-id") == custom_id

    unsafe_res = client.get("/health", headers={"X-Request-ID": "bad id with spaces/slashes!"})
    assert unsafe_res.status_code == 200
    generated = unsafe_res.headers.get("x-request-id", "")
    assert generated != "bad id with spaces/slashes!"
    uuid.UUID(generated)


def test_metrics_prometheus_and_json():
    client.post(
        "/api/v1/analyze",
        json={"text": "URGENT! Send your OTP immediately to avoid suspension"},
    )

    prom_res = client.get("/metrics")
    assert prom_res.status_code == 200
    assert prom_res.headers["content-type"].startswith("text/plain")
    assert "# TYPE cyber_dragon_http_requests_total counter" in prom_res.text
    assert "cyber_dragon_analyses_total " in prom_res.text
    _assert_security_headers(prom_res)

    json_accept = client.get("/metrics", headers={"Accept": "application/json"})
    assert json_accept.status_code == 200
    body = json_accept.json()
    assert body["service"] == "cyber-dragon-threat-api"
    assert body["requests_total"] >= 1
    assert body["analyses_total"] >= 1
    assert body["uptime_seconds"] >= 0
    _assert_security_headers(json_accept)

    json_query = client.get("/metrics?format=json")
    assert json_query.status_code == 200
    assert json_query.json()["service"] == "cyber-dragon-threat-api"


def test_global_exception_handler_sanitized(monkeypatch):
    def boom(_text: str):
        raise RuntimeError("sensitive internal traceback detail /etc/secret")

    monkeypatch.setattr(threat_main, "analyze_payload", boom)
    res = client.post(
        "/api/v1/analyze",
        json={"text": "hello world"},
        headers={"X-Request-ID": "err-trace-001"},
    )
    assert res.status_code == 500
    assert "sensitive internal traceback" not in res.text
    assert res.json() == {"detail": "Internal server error", "request_id": "err-trace-001"}
    _assert_security_headers(res)
    assert res.headers.get("x-request-id") == "err-trace-001"


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
    res = client.post(
        "/api/v1/analyze",
        content=b"x" * 17000,
        headers={"content-type": "application/json"},
    )
    assert res.status_code == 413
    _assert_security_headers(res)

    header_res = client.post(
        "/api/v1/analyze",
        content=b"{}",
        headers={"content-type": "application/json", "content-length": "25000"},
    )
    assert header_res.status_code == 413
    _assert_security_headers(header_res)


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
