# Cyber Dragon security operations

## Current release boundaries
- Stateless, deterministic local heuristics; no external URL fetching
- Do not submit sensitive personal information or secrets
- The API returns indicators, not a verified malicious/safe determination
- Production ingress **must** have per-IP and global rate limits configured before high-volume promotion
- Vercel edge WAF rules or a managed Redis-based limiter are appropriate next steps; in-memory serverless counters are not reliable across instances

## Privacy and abuse
- Do not persist raw submitted text or URLs
- Do not add request-body logging, analytics capture, or third-party reputation queries without a documented consent flow
- Validate input type and length, reject oversized bodies and unexpected content types
- Apply limits at the edge and cap concurrency/cost; measure error rates without retaining sensitive payloads

## Reputation provider integration (planned, not enabled)
- URL submissions can expose private paths and tokens to third parties
- Require explicit opt-in, domain/path minimization, clear provider identification, retention review, and contractual/license review
- Never visit submitted URLs directly from backend infrastructure
- Use independent, auditable signals and calibrate false positives and negatives

## Community reporting (planned, not enabled)
- No public accusations, phone-number listings or doxxing
- Private intake, anti-spam controls, human moderation, appeal and deletion workflows required
- Redact PII before sharing any aggregate intelligence

## Production acceptance criteria
- Passing API tests and frontend build
- Abuse rate limiting with load tests and fail-closed behavior under provider outages
- Privacy and accessibility review
- Security review of headers, dependencies, input validation, error handling, and incident response
- Monitoring with no submitted-content logging
