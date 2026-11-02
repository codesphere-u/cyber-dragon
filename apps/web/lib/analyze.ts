export type ThreatCategory =
  | 'credential_harvesting'
  | 'mobile_money_ussd_fraud'
  | 'domain_url_deception'
  | 'social_engineering_urgency'
  | 'advance_fee_investment_scam';

export type CategoryScores = Record<ThreatCategory, number>;

export type ThreatFinding = {
  id: string;
  category: ThreatCategory;
  severity: 'high' | 'medium' | 'low';
  weight: number;
  title: string;
  explanation: string;
  taxonomy: string;
};

export type UrlInspection = {
  index: number;
  scheme: string;
  registered_domain: string;
  subdomain_depth: number;
  is_ip_literal: boolean;
  is_punycode: boolean;
  is_shortener: boolean;
  has_embedded_credentials: boolean;
  redirect_params: string[];
  impersonated_brand: string | null;
  suspicious_tld: boolean;
  risk_flags: string[];
};

export type UssdInspection = {
  pattern_type: string;
  risk_summary: string;
};

export type RedactionSummary = {
  phones_detected: number;
  pins_or_otps_detected: number;
  emails_detected: number;
  urls_detected: number;
  ussd_codes_detected: number;
  secrets_detected: number;
};

export type ScanResult = {
  risk_score: number;
  risk_level: 'high' | 'elevated' | 'unknown_or_low_indicators';
  confidence: 'high_indicator_density' | 'moderate_indicator_density' | 'low_indicator_density';
  indicators: string[];
  category_scores: CategoryScores;
  findings: ThreatFinding[];
  url_inspections: UrlInspection[];
  ussd_inspections: UssdInspection[];
  redaction_summary: RedactionSummary;
  safe_next_steps: string[];
  recommendation: string;
  disclaimer: string;
};

export type IncidentReport = {
  generated_at: string;
  redacted_input: string;
  redaction_counts: RedactionSummary;
  analysis: ScanResult;
  markdown: string;
};

export type ThreatScenario = {
  id: string;
  title: string;
  region_context: string;
  mode: 'message' | 'link' | 'payment' | 'ussd';
  expected_level: 'high' | 'elevated' | 'unknown_or_low_indicators';
  sample_text: string;
  educational_note: string;
};

type HeuristicRule = {
  id: string;
  category: ThreatCategory;
  severity: 'high' | 'medium' | 'low';
  weight: number;
  pattern: RegExp;
  indicator: string;
  explanation: string;
  taxonomy: string;
};

const HEURISTIC_RULES: HeuristicRule[] = [
  {
    id: 'CRED-01',
    category: 'credential_harvesting',
    severity: 'high',
    weight: 35,
    pattern: /\b(?:pin|otp|one[- ]time password|password|verification code|security code|passcode|momo pin|secret code)\b/i,
    indicator: 'Authentication codes or credentials mentioned',
    explanation: 'Legitimate mobile money operators, banks, and messaging platforms never ask you to reply with a PIN, password, or OTP.',
    taxonomy: 'T1566 / Credential Harvesting',
  },
  {
    id: 'CRED-02',
    category: 'credential_harvesting',
    severity: 'medium',
    weight: 15,
    pattern: /\b(?:verify your account|confirm your identity|unlock your account|reactivate your account|update your kyc|sim registration suspended)\b/i,
    indicator: 'Account verification or unlock request',
    explanation: 'Attackers manufacture account lockouts or KYC suspension warnings to trick victims into surrendering credentials.',
    taxonomy: 'Social Engineering / Account Lock Lure',
  },
  {
    id: 'CRED-03',
    category: 'credential_harvesting',
    severity: 'high',
    weight: 25,
    pattern: /\b(?:share the 6[- ]digit code|sent you a code by mistake|forward the code|whatsapp verification code)\b/i,
    indicator: 'Account takeover code-forwarding lure',
    explanation: 'Scammers trigger an account recovery SMS to your phone and claim they sent it by mistake to hijack your WhatsApp, Telegram, or email.',
    taxonomy: 'OTP Hijack / Session Takeover',
  },
  {
    id: 'MOMO-01',
    category: 'mobile_money_ussd_fraud',
    severity: 'medium',
    weight: 12,
    pattern: /\b(?:mobile money|momo|mtn|airtel money|m-pesa|mpesa|agent id|cash out|float)\b/i,
    indicator: 'Mobile-money context',
    explanation: 'Mobile money references warrant independent balance verification via your official app or standard balance check before taking action.',
    taxonomy: 'Mobile Money Ecosystem Context',
  },
  {
    id: 'MOMO-02',
    category: 'mobile_money_ussd_fraud',
    severity: 'high',
    weight: 30,
    pattern: /\b(?:sent (?:you )?(?:ugx|kes|ngn|tzs|usd|shs)[^\n]{0,40}by mistake|wrongly sent|reverse the money|approve the reversal|initiate reversal|call me to reverse)\b/i,
    indicator: 'Fake mobile-money reversal social engineering pattern',
    explanation: 'Fraudsters send fake deposit notifications from personal numbers and pressure victims to "return" funds or approve a cash-out prompt.',
    taxonomy: 'Mobile Money Reversal Fraud',
  },
  {
    id: 'MOMO-03',
    category: 'mobile_money_ussd_fraud',
    severity: 'high',
    weight: 28,
    pattern: /\b(?:sim swap|upgrade your sim to 5g|block your sim card|ucc directive|communications commission|sim deactivation)\b/i,
    indicator: 'SIM-swap or telecom regulator impersonation lure',
    explanation: 'Impersonating telecom staff or regulators (such as UCC/CAK/NCC) is a common precursor to unauthorized SIM swaps and wallet drains.',
    taxonomy: 'SIM Swap / Regulator Impersonation',
  },
  {
    id: 'URG-01',
    category: 'social_engineering_urgency',
    severity: 'medium',
    weight: 15,
    pattern: /\b(?:urgent|immediately|act now|within 24 hours|within \d+ minutes|account suspended|final notice|last warning|immediate action)\b/i,
    indicator: 'Urgency or pressure language',
    explanation: 'Artificial time deadlines are designed to bypass critical thinking and prevent you from calling an official helpline.',
    taxonomy: 'Psychological Coercion / Urgency',
  },
  {
    id: 'FIN-01',
    category: 'advance_fee_investment_scam',
    severity: 'high',
    weight: 20,
    pattern: /\b(?:won|winner|prize|lottery|giveaway|congratulations|selected as a beneficiary|grant award|youth fund)\b/i,
    indicator: 'Prize or reward language',
    explanation: 'Unexpected lottery, grant, or promotion wins are frequently used to hook victims before demanding registration or unlocking fees.',
    taxonomy: 'Prize / Grant Lure',
  },
  {
    id: 'FIN-02',
    category: 'advance_fee_investment_scam',
    severity: 'high',
    weight: 30,
    pattern: /\b(?:send money|processing fee|advance fee|pay to claim|clearance fee|registration fee|release fee|tax clearance fee)\b/i,
    indicator: 'Upfront payment request',
    explanation: 'Requiring an upfront fee to unlock a prize, job placement, grant, or parcel is the defining indicator of advance-fee fraud.',
    taxonomy: 'Advance-Fee Fraud (419)',
  },
  {
    id: 'FIN-03',
    category: 'advance_fee_investment_scam',
    severity: 'high',
    weight: 25,
    pattern: /\b(?:investment returns|guaranteed profit|double your money|daily roi|risk[- ]free return|multiply your capital|crypto mining pool)\b/i,
    indicator: 'Unrealistic financial promise',
    explanation: 'Claims of guaranteed high daily or weekly returns with zero risk are characteristic of Ponzi and multiplier schemes.',
    taxonomy: 'High-Yield Investment Fraud',
  },
];

const PROTECTED_BRANDS: Record<string, string[]> = {
  mtn: ['mtn.com', 'mtn.co.ug', 'mtn.co.rw', 'mtn.com.gh', 'mtn.ng', 'mtnmomo.com'],
  airtel: ['airtel.com', 'airtel.co.ug', 'airtel.co.ke', 'airtel.com.ng'],
  mpesa: ['safaricom.co.ke', 'mpesa.in', 'vodacom.co.tz'],
  stanbic: ['stanbicbank.co.ug', 'stanbicbank.co.ke', 'stanbic.com', 'standardbank.com'],
  centenary: ['centenarybank.co.ug'],
  equity: ['equitybankgroup.com', 'equitygroupholdings.com'],
  flutterwave: ['flutterwave.com'],
  paystack: ['paystack.com'],
  chipper: ['chippercash.com'],
  ura: ['ura.go.ug'],
  nssf: ['nssfug.org'],
  whatsapp: ['whatsapp.com', 'wa.me'],
  telegram: ['telegram.org', 't.me'],
  paypal: ['paypal.com'],
  google: ['google.com', 'accounts.google.com'],
  microsoft: ['microsoft.com', 'live.com', 'office.com'],
  apple: ['apple.com', 'icloud.com'],
  binance: ['binance.com'],
};

const URL_SHORTENERS = new Set([
  'bit.ly',
  'tinyurl.com',
  't.co',
  'is.gd',
  'cutt.ly',
  'rb.gy',
  'shorturl.at',
  'ow.ly',
  'tiny.cc',
]);

const SUSPICIOUS_TLDS = new Set([
  'xyz',
  'top',
  'click',
  'loan',
  'work',
  'gq',
  'tk',
  'ml',
  'cf',
  'ga',
  'zip',
  'mov',
  'buzz',
  'icu',
  'vip',
]);

function levenshteinDistance(a: string, b: string): number {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  const prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  const curr = new Array<number>(b.length + 1);
  for (let i = 0; i < a.length; i++) {
    curr[0] = i + 1;
    for (let j = 0; j < b.length; j++) {
      const cost = a[i] === b[j] ? 0 : 1;
      curr[j + 1] = Math.min(curr[j] + 1, prev[j + 1] + 1, prev[j] + cost);
    }
    for (let j = 0; j <= b.length; j++) prev[j] = curr[j];
  }
  return prev[b.length];
}

function normalizeHomoglyphs(input: string): string {
  return input
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
    .replace(/5/g, 's')
    .replace(/@/g, 'a')
    .replace(/rn/g, 'm');
}

function getRegisteredDomain(host: string): string {
  const parts = host.split('.').filter(Boolean);
  if (parts.length <= 2) return host;
  const secondLevelSuffixes = new Set(['co', 'com', 'go', 'ac', 'org', 'net', 'or']);
  if (parts.length >= 3 && parts[parts.length - 1].length === 2 && secondLevelSuffixes.has(parts[parts.length - 2])) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

function detectBrandImpersonation(host: string): string | null {
  const cleanHost = host.toLowerCase();
  const regDomain = getRegisteredDomain(cleanHost);
  const tokens = cleanHost.split(/[.-]/).filter(Boolean);
  const primaryLabel = regDomain.split('.')[0] || '';
  const normalizedLabel = normalizeHomoglyphs(primaryLabel);

  for (const [brand, officialDomains] of Object.entries(PROTECTED_BRANDS)) {
    const isOfficial = officialDomains.some(
      (official) => cleanHost === official || cleanHost.endsWith('.' + official)
    );
    if (isOfficial) return null;

    if (tokens.includes(brand) || primaryLabel.includes(brand) || normalizedLabel.includes(brand)) {
      return brand.toUpperCase();
    }

    if (brand.length >= 5 && primaryLabel.length >= 4) {
      const dist = Math.min(
        levenshteinDistance(primaryLabel, brand),
        levenshteinDistance(normalizedLabel, brand)
      );
      if (dist === 1) {
        return brand.toUpperCase();
      }
    }
  }
  return null;
}

function inspectUssdPatterns(text: string): {
  inspections: UssdInspection[];
  findings: ThreatFinding[];
  indicators: string[];
  scoreDelta: number;
} {
  const inspections: UssdInspection[] = [];
  const findings: ThreatFinding[] = [];
  const indicators: string[] = [];
  let scoreDelta = 0;

  // Call/SMS unconditional forwarding USSD codes: *21*, **21*, *61*, *62*, *67*
  if (/(?:\*{1,2}(?:21|61|62|67)\*[^\s#]+#)/i.test(text)) {
    scoreDelta += 45;
    const msg = 'Call or SMS diversion USSD code detected (*21* / *62* / *67*)';
    indicators.push(msg);
    inspections.push({
      pattern_type: 'call_or_sms_diversion_ussd',
      risk_summary: 'Diverts incoming calls and verification OTPs to another phone number.',
    });
    findings.push({
      id: 'USSD-01',
      category: 'mobile_money_ussd_fraud',
      severity: 'high',
      weight: 45,
      title: msg,
      explanation: 'Dialing *21*, *61*, *62*, or *67* followed by a number forwards your incoming calls/OTPs to an attacker. Dial ##002# to cancel all forwarding.',
      taxonomy: 'USSD Call/OTP Diversion Attack',
    });
  }

  // Mobile money transfer / cash-out / PIN change USSD strings (*165*, *185*, *150*, *234*, *334*)
  if (/(?:\*(?:165|185|150|160|234|334)\*[\d*]+#)/i.test(text)) {
    scoreDelta += 25;
    const msg = 'Parameterized mobile-money USSD transaction string detected';
    indicators.push(msg);
    inspections.push({
      pattern_type: 'parameterized_mobile_money_ussd',
      risk_summary: 'Pre-filled USSD string that may authorize a transfer, cash-out, or PIN reset.',
    });
    findings.push({
      id: 'USSD-02',
      category: 'mobile_money_ussd_fraud',
      severity: 'high',
      weight: 25,
      title: msg,
      explanation: 'Attackers disguise money transfer or agent cash-out parameters as "prize claim" or "verification" USSD codes.',
      taxonomy: 'USSD Transaction Manipulation',
    });
  }

  return { inspections, findings, indicators, scoreDelta };
}

export function redactSensitiveText(text: string): {
  redacted_text: string;
  counts: RedactionSummary;
} {
  let phones = 0;
  let pinsOrOtps = 0;
  let emails = 0;
  let urls = 0;
  let ussdCodes = 0;
  let secrets = 0;

  let out = text;

  // Redact URLs with query tokens or credentials
  out = out.replace(/https?:\/\/[^\s<>"']+/gi, (match) => {
    urls += 1;
    try {
      const cleaned = match.replace(/[.,!?)]+$/, '');
      const u = new URL(cleaned);
      const safeHost = getRegisteredDomain(u.hostname.toLowerCase());
      return `[REDACTED-URL:${u.protocol}//${safeHost}/...]`;
    } catch {
      return '[REDACTED-MALFORMED-URL]';
    }
  });

  // Redact USSD codes
  out = out.replace(/\*[\d*#]{3,30}#/g, () => {
    ussdCodes += 1;
    return '[REDACTED-USSD-CODE]';
  });

  // Redact emails
  out = out.replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, () => {
    emails += 1;
    return '[REDACTED-EMAIL]';
  });

  // Redact East African & international phone numbers (+256..., 07..., +254..., +234...)
  out = out.replace(/(?:\+\d{1,3}[\s-]?\d{6,12}\b|\b0[78]\d{1}[\s-]?\d{3}[\s-]?\d{4}\b)/g, () => {
    phones += 1;
    return '[REDACTED-PHONE]';
  });

  // Redact high-entropy tokens/secrets
  out = out.replace(/\b(?:sk-[a-zA-Z0-9]{12,}|gh[po]_[a-zA-Z0-9]{12,}|[a-zA-Z0-9_-]{18,})\b/g, (token) => {
    if (token.startsWith('REDACTED')) return token;
    secrets += 1;
    return '[REDACTED-SECRET]';
  });

  // Redact 4 to 8 digit standalone numeric codes (PINs / OTPs)
  out = out.replace(/\b\d{4,8}\b/g, () => {
    pinsOrOtps += 1;
    return '[REDACTED-NUMERIC-CODE]';
  });

  return {
    redacted_text: out,
    counts: {
      phones_detected: phones,
      pins_or_otps_detected: pinsOrOtps,
      emails_detected: emails,
      urls_detected: urls,
      ussd_codes_detected: ussdCodes,
      secrets_detected: secrets,
    },
  };
}

export function analyzeText(text: string): ScanResult {
  const categoryScores: CategoryScores = {
    credential_harvesting: 0,
    mobile_money_ussd_fraud: 0,
    domain_url_deception: 0,
    social_engineering_urgency: 0,
    advance_fee_investment_scam: 0,
  };

  const indicators: string[] = [];
  const findings: ThreatFinding[] = [];
  const urlInspections: UrlInspection[] = [];

  for (const rule of HEURISTIC_RULES) {
    if (rule.pattern.test(text)) {
      categoryScores[rule.category] = Math.min(100, categoryScores[rule.category] + rule.weight);
      indicators.push(rule.indicator);
      findings.push({
        id: rule.id,
        category: rule.category,
        severity: rule.severity,
        weight: rule.weight,
        title: rule.indicator,
        explanation: rule.explanation,
        taxonomy: rule.taxonomy,
      });
    }
  }

  // USSD fraud inspection
  const ussd = inspectUssdPatterns(text);
  if (ussd.scoreDelta > 0) {
    categoryScores.mobile_money_ussd_fraud = Math.min(
      100,
      categoryScores.mobile_money_ussd_fraud + ussd.scoreDelta
    );
    indicators.push(...ussd.indicators);
    findings.push(...ussd.findings);
  }

  // URL & Domain Deconstruction (SSRF-free: zero external network requests)
  const urls = text.match(/https?:\/\/[^\s<>"']+/gi)?.slice(0, 10) ?? [];
  urls.forEach((raw, idx) => {
    const cleaned = raw.replace(/[.,!?)]+$/, '');
    try {
      const url = new URL(cleaned);
      const host = url.hostname.toLowerCase();
      const tld = host.split('.').pop() || '';
      const regDomain = getRegisteredDomain(host);
      const subdomainDepth = Math.max(0, host.split('.').length - regDomain.split('.').length);
      const isIp = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host);
      const isPunycode = host.startsWith('xn--') || host.includes('.xn--');
      const isShortener = URL_SHORTENERS.has(regDomain);
      const hasCreds = Boolean(url.username || url.password);
      const suspiciousTld = SUSPICIOUS_TLDS.has(tld);
      const impersonatedBrand = detectBrandImpersonation(host);
      const redirectParams: string[] = [];

      for (const param of ['redirect', 'url', 'next', 'target', 'dest', 'returnTo', 'continue']) {
        if (url.searchParams.has(param)) redirectParams.push(param);
      }

      const riskFlags: string[] = [];

      if (hasCreds) {
        categoryScores.domain_url_deception += 35;
        const msg = 'Link embeds credentials in its address';
        indicators.push(msg);
        riskFlags.push(msg);
        findings.push({
          id: 'URL-CRED',
          category: 'domain_url_deception',
          severity: 'high',
          weight: 35,
          title: msg,
          explanation: 'URLs containing user@host syntax disguise the actual destination host after the @ symbol.',
          taxonomy: 'URI Authority Obfuscation',
        });
      }

      if (isPunycode) {
        categoryScores.domain_url_deception += 25;
        const msg = 'Encoded internationalized domain; inspect spelling';
        indicators.push(msg);
        riskFlags.push(msg);
        findings.push({
          id: 'URL-IDN',
          category: 'domain_url_deception',
          severity: 'high',
          weight: 25,
          title: msg,
          explanation: 'Punycode (xn--) domains can use lookalike non-Latin characters (homographs) to impersonate trusted websites.',
          taxonomy: 'IDN Homograph Attack',
        });
      }

      if (impersonatedBrand) {
        categoryScores.domain_url_deception += 35;
        const msg = `Lookalike or unofficial domain referencing ${impersonatedBrand}`;
        indicators.push(msg);
        riskFlags.push(msg);
        findings.push({
          id: 'URL-BRAND',
          category: 'domain_url_deception',
          severity: 'high',
          weight: 35,
          title: msg,
          explanation: `The link hostname resembles ${impersonatedBrand} but is not hosted on an official ${impersonatedBrand} root domain.`,
          taxonomy: 'Brand Impersonation / Typosquatting',
        });
      }

      if (isIp) {
        categoryScores.domain_url_deception += 20;
        const msg = 'Link uses a numeric IP address';
        indicators.push(msg);
        riskFlags.push(msg);
        findings.push({
          id: 'URL-IP',
          category: 'domain_url_deception',
          severity: 'medium',
          weight: 20,
          title: msg,
          explanation: 'Legitimate banking, mobile money, and consumer portals use verifiable domain names rather than raw IP addresses.',
          taxonomy: 'Raw IP Phishing Host',
        });
      }

      if (url.protocol === 'http:') {
        categoryScores.domain_url_deception += 10;
        const msg = 'Unencrypted HTTP link';
        indicators.push(msg);
        riskFlags.push(msg);
        findings.push({
          id: 'URL-HTTP',
          category: 'domain_url_deception',
          severity: 'low',
          weight: 10,
          title: msg,
          explanation: 'Plain HTTP connections do not encrypt traffic in transit and are vulnerable to interception.',
          taxonomy: 'Unencrypted Transport',
        });
      }

      if ( host.split('.').length > 5 || subdomainDepth >= 3) {
        categoryScores.domain_url_deception += 10;
        const msg = 'Unusually deep subdomain structure';
        indicators.push(msg);
        riskFlags.push(msg);
      }

      if (url.pathname.length > 160) {
        categoryScores.domain_url_deception += 10;
        const msg = 'Unusually long URL path';
        indicators.push(msg);
        riskFlags.push(msg);
      }

      if (redirectParams.length > 0) {
        categoryScores.domain_url_deception += 10;
        const msg = 'Link includes a redirect parameter';
        indicators.push(msg);
        riskFlags.push(msg);
      }

      if (isShortener) {
        categoryScores.domain_url_deception += 15;
        const msg = 'Shortened URL hides final destination domain';
        indicators.push(msg);
        riskFlags.push(msg);
      }

      if (suspiciousTld) {
        categoryScores.domain_url_deception += 15;
        const msg = 'Domain uses a high-abuse top-level domain extension';
        indicators.push(msg);
        riskFlags.push(msg);
      }

      urlInspections.push({
        index: idx + 1,
        scheme: url.protocol.replace(':', ''),
        registered_domain: isIp ? '[IP-LITERAL]' : regDomain,
        subdomain_depth: subdomainDepth,
        is_ip_literal: isIp,
        is_punycode: isPunycode,
        is_shortener: isShortener,
        has_embedded_credentials: hasCreds,
        redirect_params: redirectParams,
        impersonated_brand: impersonatedBrand,
        suspicious_tld: suspiciousTld,
        risk_flags: riskFlags,
      });
    } catch {
      categoryScores.domain_url_deception += 10;
      indicators.push('Malformed link');
      findings.push({
        id: 'URL-MALFORMED',
        category: 'domain_url_deception',
        severity: 'low',
        weight: 10,
        title: 'Malformed link',
        explanation: 'The URL could not be parsed as a standard web address.',
        taxonomy: 'Malformed URI',
      });
    }
  });

  categoryScores.domain_url_deception = Math.min(100, categoryScores.domain_url_deception);

  const rawTotal =
    categoryScores.credential_harvesting +
    categoryScores.mobile_money_ussd_fraud +
    categoryScores.domain_url_deception +
    categoryScores.social_engineering_urgency +
    categoryScores.advance_fee_investment_scam;

  const score = Math.min(100, rawTotal);
  const riskLevel =
    score >= 60 ? 'high' : score >= 30 ? 'elevated' : 'unknown_or_low_indicators';

  const uniqueIndicators = [...new Set(indicators)];
  const confidence =
    uniqueIndicators.length >= 3
      ? 'high_indicator_density'
      : uniqueIndicators.length >= 1
        ? 'moderate_indicator_density'
        : 'low_indicator_density';

  const safeNextSteps: string[] = [];
  if (categoryScores.credential_harvesting > 0) {
    safeNextSteps.push(
      'Never reply with or enter your PIN, OTP, password, or 6-digit verification code.'
    );
  }
  if (categoryScores.mobile_money_ussd_fraud > 0) {
    safeNextSteps.push(
      'Check your real mobile money balance independently using your official app or standard balance menu before acting on any SMS.'
    );
  }
  if (ussd.inspections.some((u) => u.pattern_type === 'call_or_sms_diversion_ussd')) {
    safeNextSteps.push(
      'Do not dial the USSD string. If you already dialed a suspicious *21* or *62* code, dial ##002# immediately to clear call/SMS forwarding.'
    );
  }
  if (categoryScores.domain_url_deception > 0) {
    safeNextSteps.push(
      'Do not open the link. Navigate to the institution by typing its known official web address directly into your browser.'
    );
  }
  if (categoryScores.advance_fee_investment_scam > 0) {
    safeNextSteps.push(
      'Refuse any request for upfront processing, clearance, or unlocking fees—legitimate awards and refunds do not require advance payments.'
    );
  }
  if (safeNextSteps.length === 0) {
    safeNextSteps.push(
      'Verify unexpected messages through an independently trusted contact channel before sharing information or sending funds.'
    );
  }

  const redaction = redactSensitiveText(text);

  return {
    risk_score: score,
    risk_level: riskLevel,
    confidence,
    indicators: uniqueIndicators,
    category_scores: categoryScores,
    findings,
    url_inspections: urlInspections,
    ussd_inspections: ussd.inspections,
    redaction_summary: redaction.counts,
    safe_next_steps: safeNextSteps,
    recommendation:
      score >= 30
        ? 'Do not share PINs, OTPs or passwords. Verify unexpected requests using independently obtained official contact details.'
        : 'No strong heuristic indicators found. This does not establish safety; verify the source independently.',
    disclaimer:
      'Heuristic assessment only. No website was visited, no reputation lookup was performed, and no safety guarantee is implied.',
  };
}

export function generateIncidentReport(text: string): IncidentReport {
  const analysis = analyzeText(text);
  const { redacted_text, counts } = redactSensitiveText(text);
  const generatedAt = new Date().toISOString();

  const lines: string[] = [
    '# Cyber Dragon — Privacy-Preserving Threat Advisory Report',
    '',
    `- **Generated At:** ${generatedAt}`,
    `- **Advisory Risk Score:** ${analysis.risk_score} / 100 (${analysis.risk_level.toUpperCase()})`,
    `- **Indicator Density:** ${analysis.confidence}`,
    '',
    '## 1. Category Risk Breakdown',
    `- **Credential Harvesting:** ${analysis.category_scores.credential_harvesting}/100`,
    `- **Mobile Money & USSD Fraud:** ${analysis.category_scores.mobile_money_ussd_fraud}/100`,
    `- **Domain & URL Deception:** ${analysis.category_scores.domain_url_deception}/100`,
    `- **Social Engineering Urgency:** ${analysis.category_scores.social_engineering_urgency}/100`,
    `- **Advance-Fee & Investment Scam:** ${analysis.category_scores.advance_fee_investment_scam}/100`,
    '',
    '## 2. Triggered Heuristic Indicators',
    ...(analysis.indicators.length > 0
      ? analysis.indicators.map((ind) => `- ${ind}`)
      : ['- No strong heuristic indicators matched in this rule set.']),
    '',
    '## 3. Redacted Submission Preview (PII Scrubbed)',
    '```text',
    redacted_text,
    '```',
    '',
    '## 4. Recommended Defensive Actions',
    ...analysis.safe_next_steps.map((step, i) => `${i + 1}. ${step}`),
    '',
    `> **Disclaimer:** ${analysis.disclaimer}`,
  ];

  return {
    generated_at: generatedAt,
    redacted_input: redacted_text,
    redaction_counts: counts,
    analysis,
    markdown: lines.join('\n'),
  };
}

export const THREAT_SCENARIOS: ThreatScenario[] = [
  {
    id: 'momo-reversal-pin',
    title: 'MTN MoMo Fake Reversal & PIN Lure',
    region_context: 'East Africa (Mobile Money Social Engineering)',
    mode: 'payment',
    expected_level: 'high',
    sample_text:
      'URGENT: I have wrongly sent UGX 450,000 to your MTN Mobile Money number by mistake. Please approve the reversal prompt with your MoMo PIN immediately or call +256772123456.',
    educational_note:
      'Combine fake deposit SMS messages with urgency to trick the victim into authorizing a cash-out or entering their PIN.',
  },
  {
    id: 'ussd-call-diversion',
    title: 'USSD *21* Call & OTP Forwarding Hijack',
    region_context: 'Telecom / Account Takeover',
    mode: 'ussd',
    expected_level: 'high',
    sample_text:
      'UCC Notice: Your SIM registration is incomplete. Dial *21*0759998877# immediately to avoid SIM deactivation and receive your verification code.',
    educational_note:
      'Dialing *21*<number># forwards all calls and voice OTPs to the attacker. Cancel all forwarding immediately with ##002#.',
  },
  {
    id: 'brand-lookalike-phish',
    title: 'Stanbic / Mobile Money Lookalike Domain Phish',
    region_context: 'Banking & Credential Phishing',
    mode: 'link',
    expected_level: 'high',
    sample_text:
      'Your account is suspended due to pending KYC update. Verify your account within 24 hours at http://stanbic-uganda-verify.top/login?redirect=portal and enter your OTP.',
    educational_note:
      'Combines brand combo-squatting (stanbic-uganda-verify.top), unencrypted HTTP, a high-abuse .top TLD, and an open redirect parameter.',
  },
  {
    id: 'idn-punycode-homograph',
    title: 'IDN Punycode Homograph Domain Alert',
    region_context: 'Global / Unicode Domain Deception',
    mode: 'link',
    expected_level: 'elevated',
    sample_text:
      'Urgent security alert: confirm your identity at https://xn--pple-43d.com/verify-account',
    educational_note:
      'Uses Punycode (xn--) to render visually identical Cyrillic/Greek characters in place of ASCII letters.',
  },
  {
    id: 'ura-advance-fee-grant',
    title: 'Fake Grant / Tax Clearance Advance-Fee Scam',
    region_context: 'Public Sector / Advance-Fee Fraud',
    mode: 'payment',
    expected_level: 'high',
    sample_text:
      'Congratulations! You have been selected as a beneficiary of the Youth Grant Award. Send a processing fee of UGX 55,000 via Airtel Money to claim your funds immediately.',
    educational_note:
      'Legitimate government grants, tax refunds, and scholarships never require an upfront mobile-money processing fee.',
  },
  {
    id: 'whatsapp-otp-takeover',
    title: 'WhatsApp 6-Digit Verification Code Hijack',
    region_context: 'Messaging Account Takeover',
    mode: 'message',
    expected_level: 'high',
    sample_text:
      'Hello, I accidentally sent my WhatsApp verification code to your phone number by mistake. Please forward the 6-digit code to me urgently.',
    educational_note:
      'Forwarding that 6-digit code hands full control of your WhatsApp account to the attacker.',
  },
  {
    id: 'crypto-multiplier-ponzi',
    title: 'Guaranteed Daily Crypto Multiplier Scheme',
    region_context: 'Investment Fraud',
    mode: 'message',
    expected_level: 'elevated',
    sample_text:
      'Join our automated crypto mining pool today and double your money within 24 hours with 100% guaranteed profit!',
    educational_note:
      'Promises of guaranteed profit and doubling capital in 24 hours are classic hallmarks of high-yield investment fraud.',
  },
  {
    id: 'benign-colleague-note',
    title: 'Ordinary Colleague Meeting Reminder (Control)',
    region_context: 'Benign Control Sample',
    mode: 'message',
    expected_level: 'unknown_or_low_indicators',
    sample_text:
      'Hi team, our sprint planning meeting starts at 10:00 AM tomorrow in the Kampala office conference room. See you there!',
    educational_note:
      'Contains no threat indicators. Cyber Dragon correctly reports low indicators without claiming guaranteed safety.',
  },
];
