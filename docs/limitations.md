# Known Limitations & Safe Usage Boundaries

1. **Advisory Heuristics Only:** A low risk score (`0/100` or `unknown_or_low_indicators`) means no patterns in Cyber Dragon's current rule set matched. It **never** proves that a sender, link, or payment request is trustworthy.
2. **No Live Destination Fetching:** Because Cyber Dragon does not visit submitted URLs (to prevent SSRF and tracking-beacon activation), it cannot see what lies behind URL shorteners (`bit.ly`, `t.co`) or compromises hosted on legitimate domains.
3. **Heuristic Evasion:** Determined attackers can word messages creatively or use novel domains that do not resemble known brands. Always verify financial or account requests out-of-band using official contact channels.
4. **Regex-Based Redaction:** While `redactSensitiveText()` scrubs common phone number formats, emails, URLs, USSD strings, and 4–8 digit numeric codes, unusual free-form personal identifiers (such as physical addresses or full names) are not automatically recognized. Users should avoid pasting confidential personal records.
