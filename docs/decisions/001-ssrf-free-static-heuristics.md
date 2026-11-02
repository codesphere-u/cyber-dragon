# ADR-001: SSRF-Free Static Heuristic Architecture

- **Status:** Accepted
- **Date:** 2026-11-02

## Context

Public URL and message scanners are frequent targets for Server-Side Request Forgery (SSRF), internal port scanning, and unintended canary/tracking link activation. When a victim receives a personalized phishing link (`https://evil.example/track?user=alice`), automatically fetching that URL from a backend server confirms to the attacker that the victim's link was opened and exposes the scanner's IP infrastructure.

## Decision

Cyber Dragon performs **strictly static and structural inspection** of submitted messages, URLs, and USSD strings:
- URLs are parsed using standard URI parsers (`new URL()` in TypeScript, `urllib.parse.urlsplit()` in Python).
- Hostnames are compared lexically against protected brand allowlists, Levenshtein edit-distance thresholds, Punycode (`xn--`) prefixes, IP-literal regexes, and high-abuse TLD sets.
- No DNS lookups, WHOIS queries, TLS handshakes, or HTTP `GET`/`HEAD` requests are ever issued for submitted content.

## Consequences

- **Positive:** Complete immunity to SSRF, zero risk of triggering one-time phishing tracking beacons, sub-millisecond analysis latency (~0.28 ms per message), and full offline/browser capability.
- **Negative / Trade-off:** Cannot inspect the destination HTML DOM of shortened links (`bit.ly`, `tinyurl.com`) or newly registered domains that lack lexical indicators. This limitation is explicitly disclosed in every `ScanResult.disclaimer`.
