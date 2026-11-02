# Changelog

All notable changes to **Cyber Dragon** are documented in this file.

## [1.0.0] - 2026-11-02

### Added
- **5-Dimension Heuristic Threat Engine (`apps/web/lib/analyze.ts` & `services/threat-api/app/main.py`):**
  - Added sub-scores and structured findings across `credential_harvesting`, `mobile_money_ussd_fraud`, `domain_url_deception`, `social_engineering_urgency`, and `advance_fee_investment_scam`.
  - Added brand-impersonation lookalike & typosquatting detection for 18+ African and global financial, telecom, and public service brands (MTN, Airtel, M-Pesa, Stanbic, Centenary, Equity, Flutterwave, Paystack, Chipper, URA, NSSF, WhatsApp, Telegram, Google, Microsoft, Apple, PayPal, Binance).
  - Added USSD call/SMS diversion (`*21*`, `*61*`, `*62*`, `*67*`) and parameterized mobile-money USSD (`*165*`, `*185*`) detection with `##002#` remediation instructions.
  - Added East African Mobile Money fake reversal social-engineering detection.
- **Privacy-Preserving Redaction & Exportable Incident Reports:**
  - Added `redactSensitiveText` and `generateIncidentReport` in TypeScript and `POST /api/v1/incident-report` in FastAPI to scrub phone numbers, 4–8 digit PINs/OTPs, emails, USSD strings, secrets, and URL tokens.
- **Developer CLI (`apps/web/bin/cyber-dragon.mjs`):**
  - Added `scan`, `report`, `redact`, `scenarios`, and `benchmark` subcommands.
- **Batch Analysis Endpoint (`POST /api/v1/analyze/batch`):**
  - Supports evaluating up to 20 messages per request in `services/threat-api`.
- **Interactive Threat Scenario Library & Workbench UI (`apps/web/app/page.tsx`):**
  - Added 8 realistic threat & control presets, category score breakdown cards, URL structural deconstruction cards, and one-click `.md` incident report export.
- **Packaging & Test Suite Improvements:**
  - Added `services/threat-api/pyproject.toml` for zero-config `pytest` execution.
  - Added `"type": "module"` to `apps/web/package.json`.
  - Expanded automated tests to 12 Node.js test cases and 9 FastAPI endpoint test cases.

## [0.2.0] - 2026-10-27
- Initial early-MVP Next.js and FastAPI heuristic prototype.
