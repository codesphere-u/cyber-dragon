'use client';

import { useState, type FormEvent } from 'react';

type Analysis = {risk_score: number; risk_level: string; indicators: string[]; recommendation: string; disclaimer: string};
const tips = [
  {icon:'🔐',title:'Protect your PIN and OTP',text:'Never share passwords, PINs, or one-time codes—even with someone claiming to be support.'},
  {icon:'📱',title:'Verify mobile-money requests',text:'Call the official number you already trust. Do not use a number supplied in a suspicious message.'},
  {icon:'🔗',title:'Inspect links before opening',text:'Check the exact domain. Lookalike spelling, urgency and unexpected payment requests are warning signs.'},
  {icon:'🛡️',title:'Respond to an account takeover',text:'Change your password from a trusted device, revoke sessions, enable MFA and contact the provider.'},
];
export default function Home() {
  const [text, setText] = useState('');
  const [result, setResult] = useState<Analysis | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  async function analyze(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setLoading(true); setError(''); setResult(null);
    try {
      const response = await fetch('/api/analyze', {method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({text})});
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Unable to analyze.');
      setResult(data as Analysis);
    } catch (err) { setError(err instanceof Error ? err.message : 'Unexpected error.'); }
    finally { setLoading(false); }
  }
  const tone = result?.risk_level === 'high' ? 'high' : result?.risk_level === 'elevated' ? 'elevated' : 'unknown';
  return <main>
    <header className="nav wrap"><a href="/" className="brand" aria-label="Cyber Dragon home"><span className="brandmark">🐉</span> CYBER<span>DRAGON</span></a><nav aria-label="Main navigation"><a href="#shield">Dragon Shield</a><a href="#learn">Safety Academy</a><a href="https://github.com/codesphere-u/cyber-dragon" target="_blank" rel="noopener noreferrer">Open source ↗</a></nav></header>
    <section className="hero wrap"><div className="eyebrow">✦ COMMUNITY-POWERED DIGITAL DEFENSE</div><h1>Stay one step ahead<br/>of <em>digital threats.</em></h1><p>Suspicious message? Strange link? Understand the warning signs before you click, pay or share your information.</p><div className="heroActions"><a className="primary" href="#shield">Check a threat <span aria-hidden="true">↗</span></a><a className="secondary" href="#learn">Learn how to stay safe</a></div><div className="trust">🔒 No account required <span>•</span> 🧠 Explainable results <span>•</span> 🌍 Free and open source</div></section>
    <section className="scanner wrap" id="shield" aria-labelledby="shield-title"><div className="scannerHead"><div><span className="sectionTag">DRAGON SHIELD / 01</span><h2 id="shield-title">Check something suspicious</h2><p>Paste a suspicious message or URL. This scanner checks for common scam patterns, without opening the link.</p></div><span className="status">● HEURISTIC SCANNER</span></div><form onSubmit={analyze}><label htmlFor="threat">Message or link to analyze</label><textarea id="threat" value={text} onChange={e=>setText(e.target.value)} maxLength={8000} required placeholder="Example: Congratulations! You've won a prize. Send your mobile money PIN to claim..." rows={5}/><div className="formBottom"><span>{text.length.toLocaleString()} / 8,000 characters</span><button type="submit" disabled={loading || !text.trim()}>{loading ? 'Analyzing…' : 'Analyze threat →'}</button></div></form><p className="privacy">⚠️ Avoid submitting passwords, PINs, OTPs or private personal information. This service is an early-stage heuristic tool, not a definitive security verdict.</p>
    {error && <div className="error" role="alert">{error}</div>}
    {result && <div className={'result '+tone} role="status" aria-live="polite"><div className="resultTop"><div><span className="sectionTag">ANALYSIS COMPLETE</span><h3>{tone === 'high' ? 'High-risk warning signs' : tone === 'elevated' ? 'Some warning signs detected' : 'No strong patterns detected'}</h3></div><div className="score"><strong>{result.risk_score}</strong><small>/ 100</small></div></div><p>{result.recommendation}</p>{result.indicators.length>0 && <><h4>What we noticed</h4><ul>{result.indicators.map((item,i)=><li key={i}>{item}</li>)}</ul></>}<small className="disclaimer">{result.disclaimer}</small></div>}
    </section>
    <section className="academy wrap" id="learn"><span className="sectionTag">DRAGON ACADEMY / 02</span><h2>Knowledge is your strongest shield.</h2><p>Practical safety guidance anyone can use, anywhere.</p><div className="cards">{tips.map(tip=><article className="tip" key={tip.title}><div className="tipIcon" aria-hidden="true">{tip.icon}</div><h3>{tip.title}</h3><p>{tip.text}</p></article>)}</div></section>
    <section className="mission wrap"><div><span className="sectionTag">THE MISSION</span><h2>Built for communities.<br/>Open to the world.</h2><p>Cyber Dragon is an open-source initiative to make trustworthy digital safety tools understandable and accessible. Community reports, advanced intelligence and additional languages are on the roadmap—not live features yet.</p></div><a className="primary" href="https://github.com/codesphere-u/cyber-dragon" target="_blank" rel="noopener noreferrer">Contribute on GitHub ↗</a></section>
    <footer className="wrap footer"><strong>🐉 CYBER DRAGON</strong><span>Defend. Educate. Empower.</span><span>Apache 2.0 · Early MVP · No safety guarantees</span></footer>
  </main>;
}
