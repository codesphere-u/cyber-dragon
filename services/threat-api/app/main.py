"""Cyber Dragon Threat API v1.0: Explainable, SSRF-free defensive heuristics and PII-redacting incident reports."""
from __future__ import annotations

import logging
import re
import threading
import time
import uuid
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlsplit

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

logger = logging.getLogger("cyber_dragon.threat_api")

app = FastAPI(
    title="Cyber Dragon Threat API",
    version="1.0.0",
    description="SSRF-free static threat heuristic engine for scam messages, phishing URLs, and African Mobile Money / USSD fraud patterns.",
)
MAX_BODY = 16_384
REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Cache-Control": "no-store",
}

_START_TIME = time.monotonic()
_METRICS_LOCK = threading.Lock()
_METRICS: dict[str, int] = {
    "requests_total": 0,
    "rejected_oversized_total": 0,
    "analyses_total": 0,
    "high_risk_detections_total": 0,
    "incident_reports_total": 0,
    "unhandled_errors_total": 0,
}


def _inc_metric(name: str, delta: int = 1) -> None:
    with _METRICS_LOCK:
        _METRICS[name] = _METRICS.get(name, 0) + delta


def _snapshot_metrics() -> dict[str, int | float]:
    with _METRICS_LOCK:
        snapshot: dict[str, int | float] = dict(_METRICS)
    snapshot["uptime_seconds"] = round(time.monotonic() - _START_TIME, 3)
    return snapshot


def _resolve_request_id(request: Request) -> str:
    existing = getattr(request.state, "request_id", None)
    if isinstance(existing, str) and existing:
        return existing
    candidate = request.headers.get("x-request-id", "").strip()
    request_id = candidate if REQUEST_ID_PATTERN.fullmatch(candidate) else str(uuid.uuid4())
    request.state.request_id = request_id
    return request_id


def _apply_response_headers(response: Response, request_id: str) -> Response:
    response.headers["X-Request-ID"] = request_id
    for header, value in SECURITY_HEADERS.items():
        response.headers.setdefault(header, value)
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> Response:
    request_id = _resolve_request_id(request)
    _inc_metric("unhandled_errors_total")
    logger.error(
        "Unhandled exception request_id=%s path=%s type=%s",
        request_id,
        request.url.path,
        type(exc).__name__,
    )
    response = JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "request_id": request_id},
    )
    return _apply_response_headers(response, request_id)


@app.middleware("http")
async def security_and_size_middleware(request: Request, call_next):
    request_id = _resolve_request_id(request)
    _inc_metric("requests_total")

    content_length = request.headers.get("content-length", "")
    if content_length.isdigit() and int(content_length) > MAX_BODY:
        _inc_metric("rejected_oversized_total")
        oversized = JSONResponse(
            status_code=413,
            content={"detail": "Request too large", "request_id": request_id},
        )
        return _apply_response_headers(oversized, request_id)

    body = await request.body()
    if len(body) > MAX_BODY:
        _inc_metric("rejected_oversized_total")
        oversized = JSONResponse(
            status_code=413,
            content={"detail": "Request too large", "request_id": request_id},
        )
        return _apply_response_headers(oversized, request_id)

    try:
        response = await call_next(request)
    except Exception as exc:  # noqa: BLE001
        return await global_exception_handler(request, exc)

    return _apply_response_headers(response, request_id)


class ScanInput(BaseModel):
    text: str = Field(min_length=1, max_length=8000)


class BatchScanInput(BaseModel):
    items: list[str] = Field(min_length=1, max_length=20)


HEURISTIC_RULES = [
    (
        "CRED-01",
        "credential_harvesting",
        "high",
        35,
        r"\b(?:pin|otp|one[- ]time password|password|verification code|security code|passcode|momo pin|secret code)\b",
        "Requests or mentions sensitive authentication information",
        "Legitimate mobile money operators, banks, and messaging platforms never ask you to reply with a PIN, password, or OTP.",
        "T1566 / Credential Harvesting",
    ),
    (
        "CRED-02",
        "credential_harvesting",
        "medium",
        15,
        r"\b(?:verify your account|confirm your identity|unlock your account|reactivate your account|update your kyc|sim registration suspended)\b",
        "Account verification or unlock request",
        "Attackers manufacture account lockouts or KYC suspension warnings to trick victims into surrendering credentials.",
        "Social Engineering / Account Lock Lure",
    ),
    (
        "CRED-03",
        "credential_harvesting",
        "high",
        25,
        r"\b(?:share the 6[- ]digit code|sent you a code by mistake|forward the code|whatsapp verification code)\b",
        "Account takeover code-forwarding lure",
        "Scammers trigger an account recovery SMS to your phone and claim they sent it by mistake to hijack your account.",
        "OTP Hijack / Session Takeover",
    ),
    (
        "MOMO-01",
        "mobile_money_ussd_fraud",
        "medium",
        12,
        r"\b(?:mobile money|momo|mtn|airtel money|m-pesa|mpesa|agent id|cash out|float)\b",
        "Mobile-money context; verify requests through official channels",
        "Mobile money references warrant independent balance verification via your official app or standard menu.",
        "Mobile Money Ecosystem Context",
    ),
    (
        "MOMO-02",
        "mobile_money_ussd_fraud",
        "high",
        30,
        r"\b(?:sent (?:you )?(?:ugx|kes|ngn|tzs|usd|shs)[^\n]{0,40}by mistake|wrongly sent|reverse the money|approve the reversal|initiate reversal|call me to reverse)\b",
        "Fake mobile-money reversal social engineering pattern",
        "Fraudsters send fake deposit notifications from personal numbers and pressure victims to return funds or approve a cash-out prompt.",
        "Mobile Money Reversal Fraud",
    ),
    (
        "MOMO-03",
        "mobile_money_ussd_fraud",
        "high",
        28,
        r"\b(?:sim swap|upgrade your sim to 5g|block your sim card|ucc directive|communications commission|sim deactivation)\b",
        "SIM-swap or telecom regulator impersonation lure",
        "Impersonating telecom staff or regulators is a common precursor to unauthorized SIM swaps and wallet drains.",
        "SIM Swap / Regulator Impersonation",
    ),
    (
        "URG-01",
        "social_engineering_urgency",
        "medium",
        15,
        r"\b(?:urgent|immediately|act now|within 24 hours|within \d+ minutes|account suspended|final notice|last warning|immediate action)\b",
        "Urgency or pressure language",
        "Artificial deadlines are designed to bypass critical thinking and prevent out-of-band verification.",
        "Psychological Coercion / Urgency",
    ),
    (
        "FIN-01",
        "advance_fee_investment_scam",
        "high",
        20,
        r"\b(?:won|winner|prize|lottery|giveaway|congratulations|selected as a beneficiary|grant award|youth fund)\b",
        "Prize or reward language",
        "Unexpected lottery, grant, or promotion wins are frequently used to hook victims before demanding upfront fees.",
        "Prize / Grant Lure",
    ),
    (
        "FIN-02",
        "advance_fee_investment_scam",
        "high",
        30,
        r"\b(?:send money|processing fee|advance fee|pay to claim|clearance fee|registration fee|release fee|tax clearance fee)\b",
        "Upfront payment request",
        "Requiring an upfront fee to unlock a prize, job placement, grant, or parcel is the defining indicator of advance-fee fraud.",
        "Advance-Fee Fraud (419)",
    ),
    (
        "FIN-03",
        "advance_fee_investment_scam",
        "high",
        25,
        r"\b(?:investment returns|guaranteed profit|double your money|daily roi|risk[- ]free return|multiply your capital|crypto mining pool)\b",
        "Unrealistic financial promise",
        "Claims of guaranteed high daily or weekly returns with zero risk are characteristic of Ponzi and multiplier schemes.",
        "High-Yield Investment Fraud",
    ),
]

PROTECTED_BRANDS: dict[str, list[str]] = {
    "mtn": ["mtn.com", "mtn.co.ug", "mtn.co.rw", "mtn.com.gh", "mtn.ng", "mtnmomo.com"],
    "airtel": ["airtel.com", "airtel.co.ug", "airtel.co.ke", "airtel.com.ng"],
    "mpesa": ["safaricom.co.ke", "mpesa.in", "vodacom.co.tz"],
    "stanbic": ["stanbicbank.co.ug", "stanbicbank.co.ke", "stanbic.com", "standardbank.com"],
    "centenary": ["centenarybank.co.ug"],
    "equity": ["equitybankgroup.com", "equitygroupholdings.com"],
    "flutterwave": ["flutterwave.com"],
    "paystack": ["paystack.com"],
    "chipper": ["chippercash.com"],
    "ura": ["ura.go.ug"],
    "nssf": ["nssfug.org"],
    "whatsapp": ["whatsapp.com", "wa.me"],
    "telegram": ["telegram.org", "t.me"],
    "paypal": ["paypal.com"],
    "google": ["google.com", "accounts.google.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com"],
    "apple": ["apple.com", "icloud.com"],
    "binance": ["binance.com"],
}

URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "ow.ly", "tiny.cc"}
SUSPICIOUS_TLDS = {"xyz", "top", "click", "loan", "work", "gq", "tk", "ml", "cf", "ga", "zip", "mov", "buzz", "icu", "vip"}


def _registered_domain(host: str) -> str:
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 2:
        return host
    second_level = {"co", "com", "go", "ac", "org", "net", "or"}
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in second_level:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _detect_brand_impersonation(host: str) -> str | None:
    clean = host.lower()
    reg = _registered_domain(clean)
    primary = reg.split(".")[0] if reg else ""
    tokens = [t for t in re.split(r"[.-]", clean) if t]
    for brand, officials in PROTECTED_BRANDS.items():
        if any(clean == off or clean.endswith("." + off) for off in officials):
            return None
        if brand in tokens or brand in primary:
            return brand.upper()
    return None


def redact_sensitive_text(text: str) -> dict:
    phones = pins = emails = urls = ussd = secrets = 0

    def _repl_url(m: re.Match) -> str:
        nonlocal urls
        urls += 1
        raw = m.group(0).rstrip(".,!?)")
        try:
            sp = urlsplit(raw)
            host = _registered_domain((sp.hostname or "unknown").lower())
            return f"[REDACTED-URL:{sp.scheme}://{host}/...]"
        except ValueError:
            return "[REDACTED-MALFORMED-URL]"

    out = re.sub(r"https?://[^\s<>\"']+", _repl_url, text, flags=re.IGNORECASE)

    def _repl_ussd(_: re.Match) -> str:
        nonlocal ussd
        ussd += 1
        return "[REDACTED-USSD-CODE]"

    out = re.sub(r"\*[\d*#]{3,30}#", _repl_ussd, out)

    def _repl_email(_: re.Match) -> str:
        nonlocal emails
        emails += 1
        return "[REDACTED-EMAIL]"

    out = re.sub(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", _repl_email, out, flags=re.IGNORECASE)

    def _repl_phone(_: re.Match) -> str:
        nonlocal phones
        phones += 1
        return "[REDACTED-PHONE]"

    out = re.sub(r"(?:\+\d{1,3}[\s-]?\d{6,12}\b|\b0[78]\d{1}[\s-]?\d{3}[\s-]?\d{4}\b)", _repl_phone, out)

    def _repl_secret(m: re.Match) -> str:
        nonlocal secrets
        tok = m.group(0)
        if tok.startswith("REDACTED"):
            return tok
        secrets += 1
        return "[REDACTED-SECRET]"

    out = re.sub(r"\b(?:sk-[a-zA-Z0-9]{12,}|gh[po]_[a-zA-Z0-9]{12,}|[a-zA-Z0-9_-]{18,})\b", _repl_secret, out)

    def _repl_pin(_: re.Match) -> str:
        nonlocal pins
        pins += 1
        return "[REDACTED-NUMERIC-CODE]"

    out = re.sub(r"\b\d{4,8}\b", _repl_pin, out)

    return {
        "redacted_text": out,
        "counts": {
            "phones_detected": phones,
            "pins_or_otps_detected": pins,
            "emails_detected": emails,
            "urls_detected": urls,
            "ussd_codes_detected": ussd,
            "secrets_detected": secrets,
        },
    }


def analyze_payload(text: str) -> dict:
    lower = text.lower()
    category_scores = {
        "credential_harvesting": 0,
        "mobile_money_ussd_fraud": 0,
        "domain_url_deception": 0,
        "social_engineering_urgency": 0,
        "advance_fee_investment_scam": 0,
    }
    indicators: list[str] = []
    findings: list[dict] = []
    url_inspections: list[dict] = []
    ussd_inspections: list[dict] = []

    for rule_id, cat, sev, weight, pattern, reason, explanation, taxonomy in HEURISTIC_RULES:
        if re.search(pattern, lower):
            category_scores[cat] = min(100, category_scores[cat] + weight)
            indicators.append(reason)
            findings.append(
                {
                    "id": rule_id,
                    "category": cat,
                    "severity": sev,
                    "weight": weight,
                    "title": reason,
                    "explanation": explanation,
                    "taxonomy": taxonomy,
                }
            )

    # USSD inspection
    if re.search(r"\*{1,2}(?:21|61|62|67)\*[^\s#]+#", lower):
        category_scores["mobile_money_ussd_fraud"] = min(100, category_scores["mobile_money_ussd_fraud"] + 45)
        msg = "Call or SMS diversion USSD code detected (*21* / *62* / *67*)"
        indicators.append(msg)
        ussd_inspections.append(
            {
                "pattern_type": "call_or_sms_diversion_ussd",
                "risk_summary": "Diverts incoming calls and verification OTPs to another phone number.",
            }
        )
        findings.append(
            {
                "id": "USSD-01",
                "category": "mobile_money_ussd_fraud",
                "severity": "high",
                "weight": 45,
                "title": msg,
                "explanation": "Dialing *21*, *61*, *62*, or *67* forwards calls/OTPs to an attacker. Dial ##002# to cancel all forwarding.",
                "taxonomy": "USSD Call/OTP Diversion Attack",
            }
        )

    if re.search(r"\*(?:165|185|150|160|234|334)\*[\d*]+#", lower):
        category_scores["mobile_money_ussd_fraud"] = min(100, category_scores["mobile_money_ussd_fraud"] + 25)
        msg = "Parameterized mobile-money USSD transaction string detected"
        indicators.append(msg)
        ussd_inspections.append(
            {
                "pattern_type": "parameterized_mobile_money_ussd",
                "risk_summary": "Pre-filled USSD string that may authorize a transfer, cash-out, or PIN reset.",
            }
        )

    for idx, candidate in enumerate(re.findall(r"https?://[^\s<>\"']+", text, re.IGNORECASE)[:10], start=1):
        try:
            cleaned = candidate.rstrip(".,!?)")
            sp = urlsplit(cleaned)
            host = (sp.hostname or "").lower()
            if not host:
                raise ValueError("Missing hostname")
            reg_domain = _registered_domain(host)
            tld = host.split(".")[-1] if "." in host else ""
            is_ip = bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host))
            is_punycode = host.startswith("xn--") or ".xn--" in host
            is_shortener = reg_domain in URL_SHORTENERS
            has_creds = bool(sp.username or sp.password)
            suspicious_tld = tld in SUSPICIOUS_TLDS
            brand = _detect_brand_impersonation(host)
            qparams = parse_qs(sp.query)
            redirect_params = [
                p for p in ("redirect", "url", "next", "target", "dest", "returnTo", "continue") if p in qparams
            ]
            flags: list[str] = []

            if has_creds:
                category_scores["domain_url_deception"] += 35
                msg = "Link embeds credentials in its address"
                indicators.append(msg)
                flags.append(msg)
            if is_punycode:
                category_scores["domain_url_deception"] += 25
                msg = "Internationalized domain encoding; inspect destination carefully"
                indicators.append(msg)
                flags.append(msg)
            if brand:
                category_scores["domain_url_deception"] += 35
                msg = f"Lookalike or unofficial domain referencing {brand}"
                indicators.append(msg)
                flags.append(msg)
            if is_ip:
                category_scores["domain_url_deception"] += 20
                msg = "Link uses a numeric IP address"
                indicators.append(msg)
                flags.append(msg)
            if sp.scheme.lower() == "http":
                category_scores["domain_url_deception"] += 10
                msg = "Unencrypted HTTP link"
                indicators.append(msg)
                flags.append(msg)
            if redirect_params:
                category_scores["domain_url_deception"] += 10
                msg = "Link includes a redirect parameter"
                indicators.append(msg)
                flags.append(msg)
            if is_shortener:
                category_scores["domain_url_deception"] += 15
                msg = "Shortened URL hides final destination domain"
                indicators.append(msg)
                flags.append(msg)
            if suspicious_tld:
                category_scores["domain_url_deception"] += 15
                msg = "Domain uses a high-abuse top-level domain extension"
                indicators.append(msg)
                flags.append(msg)

            url_inspections.append(
                {
                    "index": idx,
                    "scheme": sp.scheme.lower(),
                    "registered_domain": "[IP-LITERAL]" if is_ip else reg_domain,
                    "is_ip_literal": is_ip,
                    "is_punycode": is_punycode,
                    "is_shortener": is_shortener,
                    "has_embedded_credentials": has_creds,
                    "redirect_params": redirect_params,
                    "impersonated_brand": brand,
                    "suspicious_tld": suspicious_tld,
                    "risk_flags": flags,
                }
            )
        except ValueError:
            indicators.append("Malformed URL; do not open untrusted links")
            category_scores["domain_url_deception"] += 10

    category_scores["domain_url_deception"] = min(100, category_scores["domain_url_deception"])
    score = min(100, sum(category_scores.values()))
    level = "high" if score >= 60 else "elevated" if score >= 30 else "unknown_or_low_indicators"
    unique_indicators = list(dict.fromkeys(indicators))
    confidence = (
        "high_indicator_density"
        if len(unique_indicators) >= 3
        else "moderate_indicator_density"
        if len(unique_indicators) >= 1
        else "low_indicator_density"
    )
    redaction = redact_sensitive_text(text)

    safe_steps: list[str] = []
    if category_scores["credential_harvesting"] > 0:
        safe_steps.append("Never reply with or enter your PIN, OTP, password, or verification code.")
    if category_scores["mobile_money_ussd_fraud"] > 0:
        safe_steps.append("Verify your real mobile money balance independently using your official app or menu.")
    if any(u["pattern_type"] == "call_or_sms_diversion_ussd" for u in ussd_inspections):
        safe_steps.append("Do not dial the USSD string. Dial ##002# immediately to cancel any active call/OTP forwarding.")
    if category_scores["domain_url_deception"] > 0:
        safe_steps.append("Do not open the link. Navigate to the official institution website directly.")
    if not safe_steps:
        safe_steps.append("Verify unexpected requests through an independently obtained official channel.")

    _inc_metric("analyses_total")
    if level == "high":
        _inc_metric("high_risk_detections_total")

    return {
        "risk_score": score,
        "risk_level": level,
        "confidence": confidence,
        "indicators": unique_indicators,
        "category_scores": category_scores,
        "findings": findings,
        "url_inspections": url_inspections,
        "ussd_inspections": ussd_inspections,
        "redaction_summary": redaction["counts"],
        "safe_next_steps": safe_steps,
        "recommendation": (
            "Do not share passwords, PINs or OTPs. Verify unexpected requests through official channels."
            if score >= 30
            else "No strong heuristic indicators found. This does not establish safety; verify the source independently."
        ),
        "disclaimer": (
            "Heuristic assessment only; no live reputation check, AI inference, or guarantee of safety. "
            "Content is not stored by this service."
        ),
    }


@app.api_route("/health", methods=["GET", "HEAD"])
def health():
    return {"status": "ok", "version": "1.0.0", "ssrf_protection": "zero_external_network_fetch"}


@app.api_route("/healthz", methods=["GET", "HEAD"])
def healthz():
    return {"status": "ok", "service": "cyber-dragon-threat-api", "version": "1.0.0"}


@app.api_route("/readyz", methods=["GET", "HEAD"])
def readyz():
    return {
        "status": "ready",
        "service": "cyber-dragon-threat-api",
        "version": "1.0.0",
        "ssrf_protection": "zero_external_network_fetch",
        "rules_loaded": len(HEURISTIC_RULES),
    }


@app.get("/metrics")
def metrics(request: Request):
    snap = _snapshot_metrics()
    fmt = request.query_params.get("format", "").lower()
    accept = request.headers.get("accept", "").lower()
    wants_json = fmt == "json" or (
        fmt != "prometheus" and "application/json" in accept and "text/plain" not in accept
    )
    if wants_json:
        return JSONResponse(
            content={
                "service": "cyber-dragon-threat-api",
                "version": "1.0.0",
                **snap,
            }
        )

    lines = [
        "# HELP cyber_dragon_uptime_seconds Seconds since threat API startup",
        "# TYPE cyber_dragon_uptime_seconds gauge",
        f"cyber_dragon_uptime_seconds {snap['uptime_seconds']}",
        "# HELP cyber_dragon_http_requests_total Total HTTP requests handled",
        "# TYPE cyber_dragon_http_requests_total counter",
        f"cyber_dragon_http_requests_total {snap['requests_total']}",
        "# HELP cyber_dragon_http_requests_rejected_413_total Requests rejected for exceeding body limit",
        "# TYPE cyber_dragon_http_requests_rejected_413_total counter",
        f"cyber_dragon_http_requests_rejected_413_total {snap['rejected_oversized_total']}",
        "# HELP cyber_dragon_analyses_total Total payloads analyzed",
        "# TYPE cyber_dragon_analyses_total counter",
        f"cyber_dragon_analyses_total {snap['analyses_total']}",
        "# HELP cyber_dragon_high_risk_detections_total Total payloads classified as high risk",
        "# TYPE cyber_dragon_high_risk_detections_total counter",
        f"cyber_dragon_high_risk_detections_total {snap['high_risk_detections_total']}",
        "# HELP cyber_dragon_incident_reports_total Total PII-redacted incident reports generated",
        "# TYPE cyber_dragon_incident_reports_total counter",
        f"cyber_dragon_incident_reports_total {snap['incident_reports_total']}",
        "# HELP cyber_dragon_unhandled_errors_total Total unhandled exceptions caught safely",
        "# TYPE cyber_dragon_unhandled_errors_total counter",
        f"cyber_dragon_unhandled_errors_total {snap['unhandled_errors_total']}",
    ]
    return PlainTextResponse(
        content="\n".join(lines) + "\n",
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@app.post("/api/v1/analyze")
def analyze(payload: ScanInput):
    return analyze_payload(payload.text)


@app.post("/api/v1/analyze/batch")
def analyze_batch(payload: BatchScanInput):
    results = []
    for item in payload.items:
        trimmed = item.strip()[:8000]
        if not trimmed:
            continue
        results.append(analyze_payload(trimmed))
    return {"count": len(results), "results": results}


@app.post("/api/v1/incident-report")
def incident_report(payload: ScanInput):
    _inc_metric("incident_reports_total")
    analysis = analyze_payload(payload.text)
    redacted = redact_sensitive_text(payload.text)
    generated_at = datetime.now(UTC).isoformat()
    md = "\n".join(
        [
            "# Cyber Dragon — Privacy-Preserving Threat Advisory Report",
            f"- **Generated At:** {generated_at}",
            f"- **Advisory Risk Score:** {analysis['risk_score']} / 100 ({analysis['risk_level'].upper()})",
            "",
            "## Triggered Indicators",
            *([f"- {i}" for i in analysis["indicators"]] or ["- None"]),
            "",
            "## Redacted Submission Preview",
            "```text",
            redacted["redacted_text"],
            "```",
            "",
            f"> {analysis['disclaimer']}",
        ]
    )
    return {
        "generated_at": generated_at,
        "redacted_input": redacted["redacted_text"],
        "redaction_counts": redacted["counts"],
        "analysis": analysis,
        "markdown": md,
    }
