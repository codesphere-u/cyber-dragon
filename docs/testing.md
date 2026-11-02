# Testing & Verification Guide

## 1. Automated Test Suites

### Web & CLI Engine Tests (`apps/web`)

```bash
cd apps/web
npm test
npm run benchmark
npm run lint
npm run build
```

Covers:
- High-risk credential & prize lures
- Benign control messages (ensuring no false "certified safe" claim)
- Numeric IP and redirect parameter detection without network fetching
- Embedded URI credential detection (`user:pass@host`)
- Non-echoing guarantee for sensitive tokens in `ScanResult`
- Score bounding (`[0, 100]`)
- East African Mobile Money fake reversal & PIN lures
- USSD `*21*` call/OTP diversion attacks and `##002#` remediation advice
- Brand-impersonation lookalikes vs. official domain allowlisting
- Punycode (`xn--`) IDN homograph detection
- PII redaction (`redactSensitiveText` & `generateIncidentReport`)
- 8-scenario synthetic benchmark evaluation (`100%` expected risk-level match)

### FastAPI Threat Service Tests (`services/threat-api`)

```bash
cd services/threat-api
pytest -v
```

Covers:
- `GET /health`
- `POST /api/v1/analyze` (high-risk, benign control, USSD diversion, brand lookalikes, official domains)
- `POST /api/v1/analyze/batch`
- `POST /api/v1/incident-report` (verifying PII and secret scrubbing)
- Input validation (`422` on empty text, `413` on payloads exceeding 16 KB)
