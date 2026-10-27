# Privacy and limitations

Cyber Dragon is an early-beta educational safety checker, not a forensic, malware-removal or account-recovery service.

## Private analysis (default)
When **Private on-device analysis** is enabled, text is analyzed by JavaScript running in your browser. Cyber Dragon does not send that text to its scan endpoint. The web host may still receive ordinary page requests and collect operational metadata according to its hosting configuration.

## Server analysis (optional)
If you turn off private analysis, your entered text is sent over HTTPS to Cyber Dragon's server-side scanner. The current implementation performs a deterministic heuristic check and does not intentionally persist submitted text or call external reputation providers. Do not submit secrets or other people's personal information.

## QR image handling
Where the browser supports the native BarcodeDetector API, QR images are decoded locally in the browser. The destination is displayed as text for analysis; it is not opened. Browser support varies, and decoding is not available everywhere. If unsupported, paste the destination URL yourself. Do not upload private images.

## How to interpret scores
Scores reflect a small set of weighted rules. They are **not** calibrated probabilities of fraud, threat intelligence verdicts, or guarantees. A low score does not mean safe. A high score does not establish criminality. Independent verification remains essential.

## Community safety
Do not share personal details, screenshots exposing accounts, or accusations about named individuals in public. Cyber Dragon does not currently accept public scam reports or promise recovery of lost money.

## Third-party services
No Google Safe Browsing or Web Risk API integration is active. Google Safe Browsing is restricted to non-commercial uses unless separately licensed; full-URL lookups can disclose submitted URLs. See https://developers.google.com/safe-browsing/reference and https://developers.google.com/safe-browsing/reference/Appropriate.Usage

## Contact
For vulnerabilities, follow SECURITY.md. For general contributions and documentation improvements, open a GitHub issue.
