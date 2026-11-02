# Cyber Dragon System Architecture

## 1. Architectural Principles

1. **Zero-Network-Fetch (SSRF-Free by Construction):** Cyber Dragon never resolves DNS, opens sockets, or makes HTTP requests to user-submitted URLs. All URL and domain analysis is performed lexically and structurally on the parsed URI components.
2. **Privacy-First On-Device Default:** In the web application (`apps/web`), "Private on-device analysis" is enabled by default, executing `analyzeText()` and `generateIncidentReport()` entirely inside the user's browser tab without transmitting input to any server.
3. **Cross-Runtime Heuristic Parity:** Both the TypeScript engine (`apps/web/lib/analyze.ts`) and the Python FastAPI service (`services/threat-api/app/main.py`) enforce the same 5-dimension scoring model, brand lookalike rules, USSD diversion checks, and PII redaction rules.
4. **Non-Echoing Scan Results:** To prevent accidental credential logging, `ScanResult` objects never echo raw user-submitted secrets or URL query strings.

## 2. Component Overview

- **`apps/web/lib/analyze.ts`**: Core TypeScript analysis engine, Levenshtein/homoglyph brand-impersonation detector, USSD inspector, PII scrubber, and Markdown incident report builder.
- **`apps/web/bin/cyber-dragon.mjs`**: Standalone Node.js CLI supporting `scan`, `report`, `redact`, `scenarios`, and `benchmark`.
- **`apps/web/app/page.tsx`**: Interactive Next.js 15 Threat Workbench with 4 inspection modes, 8 curated fraud scenarios, 5-dimension category breakdown, and QR code local decoding.
- **`services/threat-api/app/main.py`**: Stateless FastAPI microservice with bounded payload middleware (`MAX_BODY = 16,384` bytes), single & batch analysis endpoints, and incident report generation.
