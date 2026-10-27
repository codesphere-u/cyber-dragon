# Cyber Dragon implementation plan

## Principles
Privacy by default; accessibility and mobile-first UX; explainable security advice; no public naming-and-shaming without evidence and moderation; no offensive exploitation features.

## Architecture
- `apps/web`: planned Next.js TypeScript user interface
- `services/threat-api`: working FastAPI heuristic analyzer (stateless)
- Future PostgreSQL/Supabase: accounts, opt-in reports, moderation and audit trail (not needed for MVP)
- Future workers: licensed threat feeds and scheduled aggregation, never automatic submission of sensitive URLs
- Future services: community reporting, academy, SOS guidance, developer scanning, intelligence dashboard

## Phase 1 — Days 1–15
[x] FastAPI API, deterministic scoring, tests, CI, documentation
[ ] Build Next.js responsive UI, accessibility and localization
[ ] Threat-model review, rate limiting at reverse proxy, production CORS and CSP

## Phase 2 — Days 16–30
[ ] Privacy-preserving browser extension and shareable warnings
[ ] Reputation provider integration with consent, caching and license review
[ ] Metrics for false positives, false negatives and user comprehension

## Phase 3 — Days 31–60
[ ] Opt-in community reports, deduplication, moderation, appeal and deletion
[ ] Uganda-first scam awareness library, English and Luganda translations
[ ] Beta pilot with local community organizations

## Phase 4 — Days 61–90
[ ] Dragon Academy, open contributor onboarding and documented public API
[ ] Community partnerships, security review, load testing and deployment

## Threat model and release gates
- Never fetch arbitrary user-provided URLs in backend analysis (SSRF)
- Avoid storing or logging raw submitted text, URLs, phone numbers or PII
- Limit body sizes, sanitize UI output, protect against abuse, enforce rate limits
- Keep scoring explanations honest; do not claim an item is verified safe
- No public reports until moderation, privacy controls and appeals exist
- Require tests, code review and vulnerability checks before deployment

## Future module milestones
Dragon Shield: scam and link checks; Dragon Watch: moderated reports; Dragon Academy: training; Dragon Guard: defensive developer tooling; Dragon SOS: incident response checklists; Dragon Intel: aggregated, privacy-preserving trends.
