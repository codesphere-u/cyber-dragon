"""Cyber Dragon MVP: explainable, stateless heuristics only."""
import re
from urllib.parse import urlsplit
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

app = FastAPI(title="Cyber Dragon Threat API", version="0.1.0")
MAX_BODY = 16_384

@app.middleware("http")
async def request_size_guard(request: Request, call_next):
    if request.headers.get("content-length", "").isdigit() and int(request.headers["content-length"]) > MAX_BODY:
        return JSONResponse(status_code=413, content={"detail": "Request too large"})
    body = await request.body()
    if len(body) > MAX_BODY:
        return JSONResponse(status_code=413, content={"detail": "Request too large"})
    return await call_next(request)

class ScanInput(BaseModel):
    text: str = Field(min_length=1, max_length=8000)

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/api/v1/analyze")
def analyze(payload: ScanInput):
    text = payload.text
    lower = text.lower()
    indicators = []
    score = 0
    rules = [
        (r"\b(?:pin|otp|one.time password|password|verification code)\b", 35, "Requests or mentions sensitive authentication information"),
        (r"\b(?:won|winner|prize|lottery|giveaway|congratulations)\b", 20, "Prize or reward language"),
        (r"\b(?:urgent|immediately|act now|within 24 hours|account suspended)\b", 15, "Urgency or pressure language"),
        (r"\b(?:send money|processing fee|advance fee|pay to claim)\b", 30, "Upfront payment request"),
        (r"\b(?:mobile money|momo|mtn|airtel money)\b", 10, "Mobile-money context; verify requests through official channels"),
    ]
    for pattern, weight, reason in rules:
        if re.search(pattern, lower):
            score += weight
            indicators.append(reason)
    for candidate in re.findall(r"https?://[^\s<>\"']+", text, re.IGNORECASE)[:10]:
        try:
            host = urlsplit(candidate.rstrip(".,!?)")).hostname or ""
            if host.startswith("xn--") or ".xn--" in host:
                score += 25
                indicators.append("Internationalized domain encoding; inspect destination carefully")
            if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
                score += 20
                indicators.append("Link uses a numeric IP address")
        except ValueError:
            indicators.append("Malformed URL; do not open untrusted links")
            score += 10
    score = min(100, score)
    level = "high" if score >= 60 else "elevated" if score >= 30 else "unknown_or_low_indicators"
    return {
        "risk_score": score,
        "risk_level": level,
        "indicators": list(dict.fromkeys(indicators)),
        "recommendation": "Do not share passwords, PINs or OTPs. Verify unexpected requests through official channels." if score >= 30 else "No strong heuristic indicators found. This does not establish safety; verify the source independently.",
        "disclaimer": "Heuristic assessment only; no live reputation check, AI inference, or guarantee of safety. Content is not stored by this service.",
    }
