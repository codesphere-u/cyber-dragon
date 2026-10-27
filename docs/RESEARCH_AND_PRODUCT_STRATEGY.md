# Cyber Dragon — Research-led product strategy (October 2026)

## Evidence and implications
1. CISA phishing guidance: urgency, requests for private information, suspicious URLs and impersonation are important warning signs. Design implication: readable explanations and a verify-independently action, not a binary "safe" badge. Source: https://www.cisa.gov/sites/default/files/2024-02/Update%20to%20Phishing%20General%20Security%20Postcard_01.01.2024.pdf
2. FBI QR-code fraud warning: QR codes can conceal malicious destinations. Design implication: allow users to paste a QR destination now; add local on-device QR decoding later without automatically visiting links. Source: https://www.fbi.gov/investigate/cyber/alerts/2025/unsolicited-packages-containing-qr-codes-used-to-initiate-fraud-schemes
3. W3C WCAG 2.2 mobile guidance: meaningful labels, touch targets, contrast, reflow, focus and status announcements are essential. Design implication: keyboard-accessible buttons, visible labels, accessible result status, responsive single-column layouts and reduced-motion support. Source: https://www.w3.org/TR/wcag2mobile-22/
4. Google Safe Browsing: lookup methods can disclose submitted URLs and API terms differ by commercial use. Design implication: do not send user-submitted links to external providers without opt-in and licensing/privacy review. Source: https://developers.google.com/safe-browsing/v4/

## Released in 0.5
- Guided message, URL and payment-scam entry modes (all currently use the same documented heuristic engine)
- Contextual sample messages; no need to submit real sensitive data to try the tool
- Explainable assessment, warning indicators, next steps and copyable summary (excluding the original submitted content)
- Mobile-first redesigned interface with visible focus and reduced-motion support
- Direct access to response playbooks

## Release gates still outstanding
- No distributed rate limiting: not approved for large-scale public promotion
- No validated accuracy study or calibrated risk model: numerical scores are heuristic, not statistical probabilities
- No external reputation feed, QR decoding, image upload or AI inference
- No vetted localization yet: translations should be reviewed by fluent speakers
- No user-submitted public allegations or open threat database without moderation, appeals and privacy protections

## Next implementation milestones
1. Add distributed per-client rate limiting and WAF protections; run privacy and abuse tests.
2. Assemble consented, anonymized, diverse evaluation examples across languages and scam types. Track precision, recall and false-positive cost.
3. Add a privacy-preserving QR decoder running in the browser, displaying the URL without visiting it.
4. Add opt-in reputation intelligence with a documented provider, legal review, URL minimization and retention policy.
5. Conduct WCAG 2.2 AA audit and usability testing on low-end Android devices and slow connections.
6. Pilot community education with multilingual human-reviewed content and country-specific reporting links.
