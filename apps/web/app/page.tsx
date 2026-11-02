'use client';

import { useState, type FormEvent } from 'react';
import Link from 'next/link';
import {
  analyzeText,
  generateIncidentReport,
  THREAT_SCENARIOS,
  type ScanResult,
  type ThreatCategory,
} from '../lib/analyze';

type Mode = 'message' | 'link' | 'payment' | 'ussd';

const CATEGORY_LABELS: Record<ThreatCategory, string> = {
  credential_harvesting: 'Credential & OTP Harvesting',
  mobile_money_ussd_fraud: 'Mobile Money & USSD Fraud',
  domain_url_deception: 'Domain & URL Deception',
  social_engineering_urgency: 'Social Engineering Urgency',
  advance_fee_investment_scam: 'Advance-Fee & Investment Fraud',
};

const modes: { id: Mode; icon: string; title: string; description: string }[] = [
  { id: 'message', icon: '✉', title: 'Message Check', description: 'SMS, WhatsApp, email or chat' },
  { id: 'link', icon: '↗', title: 'Domain & Link Lab', description: 'Homographs, brand lookalikes & QR' },
  { id: 'payment', icon: '◈', title: 'Mobile Money & Fraud', description: 'MoMo reversals & advance fees' },
  { id: 'ussd', icon: '⌗', title: 'USSD & SIM Safety', description: '*21* call forwarding & *165* traps' },
];

const steps = [
  {
    number: '01',
    title: 'Pause before dialing or replying',
    text: 'Scammers manufacture urgency, fear, or excitement so you act before verifying. Take 60 seconds to inspect the request.',
  },
  {
    number: '02',
    title: 'Verify balances & alerts out-of-band',
    text: 'Never trust an SMS deposit alert alone. Check your real wallet balance using your official app or standard menu, and never dial unfamiliar *21* or *165* strings.',
  },
  {
    number: '03',
    title: 'Guard your PIN, OTP & SIM',
    text: 'Telecom operators, banks, and regulators never ask for your PIN or 6-digit verification code. Dial ##002# immediately if you suspect call forwarding.',
  },
];

export default function Home() {
  const [mode, setMode] = useState<Mode>('payment');
  const [value, setValue] = useState('');
  const [result, setResult] = useState<ScanResult | null>(null);
  const [reportMarkdown, setReportMarkdown] = useState<string>('');
  const [showReport, setShowReport] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);
  const [privateMode, setPrivateMode] = useState(true);
  const [qrError, setQrError] = useState('');
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>('');

  async function runAnalysis(inputText: string) {
    setBusy(true);
    setError('');
    setCopied(false);
    try {
      if (privateMode) {
        const localScan = analyzeText(inputText);
        const localReport = generateIncidentReport(inputText);
        setResult(localScan);
        setReportMarkdown(localReport.markdown);
        return;
      }
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ text: inputText }),
        cache: 'no-store',
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Could not check this content.');
      setResult(data as ScanResult);
      setReportMarkdown(generateIncidentReport(inputText).markdown);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Something went wrong.');
    } finally {
      setBusy(false);
    }
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    await runAnalysis(value);
  }

  async function decodeQr(file: File) {
    setQrError('');
    setResult(null);
    if (file.size > 5_000_000) {
      setQrError('Choose an image under 5 MB.');
      return;
    }
    if (!['image/png', 'image/jpeg', 'image/webp'].includes(file.type)) {
      setQrError('Choose a PNG, JPEG or WebP image.');
      return;
    }
    const BrowserDetector = (
      window as unknown as {
        BarcodeDetector?: new (options: { formats: string[] }) => {
          detect(source: ImageBitmap): Promise<Array<{ rawValue: string }>>;
        };
      }
    ).BarcodeDetector;
    if (!BrowserDetector) {
      setQrError('QR decoding is not supported in this browser. Paste the QR destination URL instead.');
      return;
    }
    try {
      const image = await createImageBitmap(file);
      try {
        const codes = await new BrowserDetector({ formats: ['qr_code'] }).detect(image);
        if (!codes.length) {
          setQrError('No QR code found. Try a clearer image.');
          return;
        }
        const destination = codes[0].rawValue;
        if (destination.length > 8000) {
          setQrError('The QR content is too long.');
          return;
        }
        setMode('link');
        setValue(destination);
      } finally {
        image.close();
      }
    } catch {
      setQrError('Could not read that image. Try a clearer image or paste the destination URL.');
    }
  }

  function chooseMode(next: Mode) {
    setMode(next);
    setResult(null);
    setError('');
    setSelectedScenarioId('');
  }

  function selectScenario(scenarioId: string) {
    const sc = THREAT_SCENARIOS.find((s) => s.id === scenarioId);
    if (!sc) return;
    setSelectedScenarioId(sc.id);
    setMode(sc.mode);
    setValue(sc.sample_text);
    void runAnalysis(sc.sample_text);
  }

  async function copyResult() {
    if (!result) return;
    const textToCopy = showReport
      ? reportMarkdown
      : [
          'Cyber Dragon — Advisory Threat Report',
          `Risk level: ${result.risk_level.toUpperCase()} (${result.risk_score}/100)`,
          `Indicator density: ${result.confidence}`,
          ...result.indicators.map((i) => '- ' + i),
          'Next steps:',
          ...result.safe_next_steps.map((s) => '-> ' + s),
          result.disclaimer,
        ].join('\n');
    try {
      await navigator.clipboard.writeText(textToCopy);
      setCopied(true);
    } catch {
      setError('Copy failed. You can select the results manually.');
    }
  }

  function downloadMarkdownReport() {
    if (!reportMarkdown) return;
    const blob = new Blob([reportMarkdown], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cyber-dragon-incident-report.md`;
    a.click();
    URL.revokeObjectURL(url);
  }

  const severity =
    result?.risk_level === 'high'
      ? 'high'
      : result?.risk_level === 'elevated'
        ? 'elevated'
        : 'unknown';

  return (
    <main>
      <a href="#main-content" className="skip">
        Skip to content
      </a>
      <header className="nav wrap">
        <Link href="/" className="brand">
          <span className="brandmark" aria-hidden="true">
            🐉
          </span>
          CYBER<span>DRAGON</span>
        </Link>
        <nav aria-label="Main navigation">
          <a href="#shield">Threat Workbench</a>
          <a href="#scenarios">Scenario Library</a>
          <Link href="/learn">Safety Academy</Link>
          <a
            href="https://github.com/codesphere-u/cyber-dragon"
            target="_blank"
            rel="noopener noreferrer"
          >
            GitHub ↗
          </a>
        </nav>
      </header>

      <section className="hero wrap" id="main-content">
        <div className="heroContent">
          <div className="eyebrow">
            <span className="pulse" aria-hidden="true" /> OPEN-SOURCE COMMUNITY CYBER DEFENSE · v1.0
          </div>
          <h1>
            Scams are getting smarter.
            <br />
            <em>Defend with evidence.</em>
          </h1>
          <p>
            Inspect suspicious SMS messages, phishing domains, Mobile Money reversal traps, and USSD
            diversion codes. Get explainable risk breakdowns and PII-redacted incident reports—with
            zero external link visits.
          </p>
          <div className="heroActions">
            <a href="#shield" className="primary">
              Launch Threat Workbench <span aria-hidden="true">↗</span>
            </a>
            <Link href="/learn" className="secondary">
              Emergency Response Guides
            </Link>
          </div>
          <div className="trust">
            <span>✓ 100% SSRF-Free Static Analysis</span>
            <span>✓ Mobile Money & USSD Aware</span>
            <span>✓ Automatic PII Redaction</span>
            <span>✓ CLI & FastAPI Included</span>
          </div>
        </div>
        <div className="heroVisual" aria-hidden="true">
          <div className="visualGlow" />
          <div className="visualShield">
            <span>◈</span>
            <strong>
              DRAGON
              <br />
              SHIELD
            </strong>
            <small>EXPLAINABLE HEURISTIC ENGINE</small>
          </div>
          <div className="visualTag top">◉ IDN & BRAND LOOKALIKES</div>
          <div className="visualTag bottom">✧ ZERO NETWORK FETCH</div>
        </div>
      </section>

      <section className="scanner wrap" id="shield" aria-labelledby="shield-title">
        <div className="scannerHead">
          <div>
            <span className="sectionTag">01 / DRAGON SHIELD WORKBENCH</span>
            <h2 id="shield-title">Inspect a suspicious message, URL, or USSD code</h2>
            <p>
              Select an inspection mode or load a realistic fraud scenario below to see how Cyber
              Dragon deconstructs digital threats without opening untrusted links.
            </p>
          </div>
          <span className="status">● ENGINE v1.0 READY</span>
        </div>

        <div className="modeGrid" role="group" aria-label="Check type">
          {modes.map((item) => (
            <button
              type="button"
              key={item.id}
              className={'modeCard ' + (mode === item.id ? 'selected' : '')}
              aria-pressed={mode === item.id}
              onClick={() => chooseMode(item.id)}
            >
              <span className="modeIcon" aria-hidden="true">
                {item.icon}
              </span>
              <span>
                <strong>{item.title}</strong>
                <small>{item.description}</small>
              </span>
            </button>
          ))}
        </div>

        <div className="scenarioBar" id="scenarios">
          <div className="scenarioHeader">
            <strong>Interactive Threat Scenario Library (8 Verified Presets):</strong>
            <span>Click any scenario to run an instant explainable analysis</span>
          </div>
          <div className="scenarioPills">
            {THREAT_SCENARIOS.map((sc) => (
              <button
                type="button"
                key={sc.id}
                className={
                  'scenarioPill ' +
                  (selectedScenarioId === sc.id ? 'active ' : '') +
                  sc.expected_level
                }
                onClick={() => selectScenario(sc.id)}
              >
                {sc.title}
              </button>
            ))}
          </div>
        </div>

        <div className="privacyToggle">
          <label>
            <input
              type="checkbox"
              checked={privateMode}
              onChange={(e) => setPrivateMode(e.target.checked)}
            />{' '}
            <strong>Private on-device analysis (Zero server transmission)</strong>
          </label>
          <span>
            {privateMode
              ? 'Your input is analyzed locally in this browser tab. Nothing leaves your device.'
              : 'Your text will be sent over HTTPS to the stateless Cyber Dragon API.'}
          </span>
        </div>

        {mode === 'link' && (
          <div className="qrUpload">
            <label htmlFor="qr-image">Or decode a QR code from an image on your device</label>
            <input
              id="qr-image"
              type="file"
              accept="image/png,image/jpeg,image/webp"
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) void decodeQr(file);
                e.target.value = '';
              }}
            />
            <p>QR decoding happens locally in your browser. Cyber Dragon never visits the decoded URL.</p>
            {qrError && <p role="alert">{qrError}</p>}
          </div>
        )}

        <form onSubmit={submit}>
          <div className="formTitle">
            <label htmlFor="threat">
              {mode === 'link'
                ? 'Paste a suspicious website URL or QR destination'
                : mode === 'payment'
                  ? 'Paste a Mobile Money, bank, or grant payment message'
                  : mode === 'ussd'
                    ? 'Paste a message containing a USSD code (*165*, *21*, etc.)'
                    : 'Paste an SMS, WhatsApp, email, or chat message'}
            </label>
            <button
              type="button"
              className="sample"
              onClick={() => {
                const matching =
                  THREAT_SCENARIOS.find((s) => s.mode === mode) ?? THREAT_SCENARIOS[0];
                selectScenario(matching.id);
              }}
            >
              Load sample for this mode →
            </button>
          </div>
          <textarea
            id="threat"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            maxLength={8000}
            required
            rows={5}
            placeholder={
              mode === 'link'
                ? 'https://stanbic-uganda-verify.top/login?redirect=portal'
                : mode === 'ussd'
                  ? 'Dial *21*0759998877# immediately to verify your SIM...'
                  : 'Paste suspicious text, SMS, or URL here...'
            }
          />
          <div className="formBottom">
            <span>{value.length.toLocaleString()} / 8,000 characters</span>
            <button type="submit" disabled={busy || !value.trim()}>
              {busy ? 'Analyzing indicators…' : 'Analyze Threat Indicators →'}
            </button>
          </div>
        </form>

        <p className="privacy">
          🔒 <strong>Privacy & Safety Guarantee:</strong> Never paste real passwords or active PINs.
          Incident reports automatically scrub phone numbers, 4–8 digit codes, emails, and URLs.
          Heuristic checks do not guarantee a message or link is safe.
        </p>

        {error && (
          <div role="alert" className="error">
            {error}
          </div>
        )}

        {result && (
          <div className={'result ' + severity} role="status" aria-live="polite">
            <div className="resultTop">
              <div>
                <span className="sectionTag">
                  EXPLAINABLE THREAT ASSESSMENT · {result.confidence.replace(/_/g, ' ').toUpperCase()}
                </span>
                <h3>
                  {severity === 'high'
                    ? 'High-risk fraud or phishing indicators detected'
                    : severity === 'elevated'
                      ? 'Elevated warning signs detected'
                      : 'No strong heuristic indicators matched'}
                </h3>
                <p className="resultSub">
                  Deterministic static analysis across 5 threat dimensions. No external URLs were
                  fetched.
                </p>
              </div>
              <div className="score">
                <strong>{result.risk_score}</strong>
                <small>/ 100</small>
              </div>
            </div>

            <div className="resultBar" aria-hidden="true">
              <span style={{ width: result.risk_score + '%' }} />
            </div>

            <div className="categoryGrid">
              {(Object.keys(CATEGORY_LABELS) as ThreatCategory[]).map((cat) => {
                const scoreVal = result.category_scores[cat];
                return (
                  <div className="categoryCard" key={cat}>
                    <div className="categoryHead">
                      <span>{CATEGORY_LABELS[cat]}</span>
                      <strong>{scoreVal}/100</strong>
                    </div>
                    <div className="miniBar">
                      <span style={{ width: `${scoreVal}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>

            {result.findings.length > 0 && (
              <div className="findingsSection">
                <h4>Triggered Heuristic Evidence ({result.findings.length})</h4>
                <div className="findingsGrid">
                  {result.findings.map((f, idx) => (
                    <article className={'findingCard ' + f.severity} key={f.id + idx}>
                      <div className="findingMeta">
                        <span className="badgeCode">{f.id}</span>
                        <span className="badgeTax">{f.taxonomy}</span>
                        <span className="badgeWeight">+{f.weight} pts</span>
                      </div>
                      <h5>{f.title}</h5>
                      <p>{f.explanation}</p>
                    </article>
                  ))}
                </div>
              </div>
            )}

            {result.url_inspections.length > 0 && (
              <div className="urlSection">
                <h4>Structural URL & Domain Deconstruction (Zero Network Fetch)</h4>
                <div className="urlList">
                  {result.url_inspections.map((u) => (
                    <div className="urlCard" key={u.index}>
                      <div className="urlCardHeader">
                        <strong>
                          Link #{u.index}: {u.scheme}://{u.registered_domain}
                        </strong>
                        {u.impersonated_brand && (
                          <span className="brandAlert">
                            ⚠ Brand Lookalike: {u.impersonated_brand}
                          </span>
                        )}
                      </div>
                      <div className="urlMetaBadges">
                        <span>Subdomain depth: {u.subdomain_depth}</span>
                        <span>Punycode/IDN: {u.is_punycode ? 'YES (⚠)' : 'No'}</span>
                        <span>IP Literal: {u.is_ip_literal ? 'YES (⚠)' : 'No'}</span>
                        <span>Suspicious TLD: {u.suspicious_tld ? 'YES (⚠)' : 'No'}</span>
                        <span>
                          Redirect params:{' '}
                          {u.redirect_params.length ? u.redirect_params.join(', ') : 'None'}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <h4>Recommended Defensive Next Steps</h4>
            <ul className="nextStepsList">
              {result.safe_next_steps.map((step, idx) => (
                <li key={idx}>{step}</li>
              ))}
            </ul>

            <div className="redactionSummaryBox">
              <strong>Privacy Redaction Audit:</strong> Scrubbed{' '}
              {result.redaction_summary.phones_detected} phone(s),{' '}
              {result.redaction_summary.pins_or_otps_detected} numeric code(s),{' '}
              {result.redaction_summary.urls_detected} URL(s),{' '}
              {result.redaction_summary.ussd_codes_detected} USSD string(s), and{' '}
              {result.redaction_summary.emails_detected} email(s) from the exportable incident
              report.
            </div>

            <div className="resultActions">
              <button type="button" className="secondaryButton" onClick={copyResult}>
                {copied ? '✓ Copied to clipboard' : 'Copy advisory summary'}
              </button>
              <button
                type="button"
                className="secondaryButton"
                onClick={() => setShowReport(!showReport)}
              >
                {showReport ? 'Hide PII-Redacted Report' : 'Preview PII-Redacted Report'}
              </button>
              <button type="button" className="secondaryButton" onClick={downloadMarkdownReport}>
                Download .md Incident Report ↓
              </button>
              <Link href="/learn" className="secondary">
                Emergency response playbooks ↗
              </Link>
            </div>

            {showReport && (
              <pre className="reportPreview" aria-label="PII-redacted markdown incident report">
                {reportMarkdown}
              </pre>
            )}

            <small className="disclaimer">{result.disclaimer}</small>
          </div>
        )}
      </section>

      <section className="how wrap">
        <div>
          <span className="sectionTag">02 / DEFENSIVE HABITS</span>
          <h2>Three habits that stop most digital fraud.</h2>
          <p>
            Even against new scam templates, these three verification steps protect your accounts
            and mobile wallets.
          </p>
        </div>
        <div className="howGrid">
          {steps.map((s) => (
            <article className="howCard" key={s.number}>
              <span>{s.number}</span>
              <h3>{s.title}</h3>
              <p>{s.text}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="helpBanner wrap">
        <div>
          <span className="sectionTag">03 / DRAGON ACADEMY</span>
          <h2>Already clicked a link, dialed a code, or sent money?</h2>
          <p>
            Follow step-by-step containment guides for Mobile Money fraud, USSD call forwarding
            (`##002#`), WhatsApp OTP hijacks, and credential leaks.
          </p>
        </div>
        <Link href="/learn" className="primary">
          Open emergency response guides ↗
        </Link>
      </section>

      <section className="mission wrap">
        <div>
          <span className="sectionTag">OPEN SOURCE · CLI & FASTAPI</span>
          <h2>Built for communities, developers, and security responders.</h2>
          <p>
            Run Cyber Dragon in the browser, via the Node.js CLI (`npx cyber-dragon scan`), or as a
            self-hosted FastAPI microservice (`services/threat-api`).
          </p>
        </div>
        <a
          className="secondary"
          href="https://github.com/codesphere-u/cyber-dragon"
          target="_blank"
          rel="noopener noreferrer"
        >
          View Source & CLI Docs on GitHub ↗
        </a>
      </section>

      <footer className="footer wrap">
        <strong>🐉 CYBER DRAGON v1.0</strong>
        <span>Defend. Educate. Empower.</span>
        <span>SSRF-Free Static Heuristics · Advisory Results Only · Apache-2.0 License</span>
      </footer>
    </main>
  );
}
