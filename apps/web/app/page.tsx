'use client';
import { useState, type FormEvent } from 'react';
import Link from 'next/link';
import { analyzeText } from '../lib/analyze';

type Analysis={risk_score:number;risk_level:string;indicators:string[];recommendation:string;disclaimer:string};
type Mode='message'|'link'|'payment';
const samples:Record<Mode,string>={
 message:'Congratulations! You won a prize. Urgent: send your OTP to claim your reward.',
 link:'http://192.168.1.100/verify-account?redirect=https://example.com',
 payment:'Your mobile money account is suspended. Send your PIN immediately to unlock your account.'
};
const modes:{id:Mode;icon:string;title:string;description:string}[]=[
 {id:'message',icon:'✉',title:'Message check',description:'SMS, email or chat'},
 {id:'link',icon:'↗',title:'Link check',description:'Website or QR destination'},
 {id:'payment',icon:'◈',title:'Payment scam',description:'Money and account alerts'}
];
const steps=[
 {number:'01',title:'Pause before responding',text:'Scammers often manufacture urgency, fear or excitement. You can take time to verify.'},
 {number:'02',title:'Check through a trusted channel',text:'Open the official app or type the official website yourself. Never rely on contact details inside a suspicious message.'},
 {number:'03',title:'Protect your access',text:'Do not share PINs, passwords or one-time codes. Enable multifactor authentication where possible.'}
];
export default function Home(){
 const [mode,setMode]=useState<Mode>('message');
 const [value,setValue]=useState('');
 const [result,setResult]=useState<Analysis|null>(null);
 const [busy,setBusy]=useState(false);
 const [error,setError]=useState('');
 const [copied,setCopied]=useState(false);
 const [privateMode,setPrivateMode]=useState(true);
 const [qrError,setQrError]=useState('');
 async function submit(event:FormEvent<HTMLFormElement>){
  event.preventDefault();setBusy(true);setError('');setResult(null);setCopied(false);
  try{
   if(privateMode){setResult(analyzeText(value));return;}
   const response=await fetch('/api/analyze',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({text:value}),cache:'no-store'});
   const data=await response.json();
   if(!response.ok)throw new Error(data.error||'Could not check this content.');
   setResult(data as Analysis);
  }catch(e){setError(e instanceof Error?e.message:'Something went wrong.');}
  finally{setBusy(false);}
 }
 async function decodeQr(file:File){
  setQrError('');setResult(null);
  if(file.size>5_000_000){setQrError('Choose an image under 5 MB.');return;}
  if(!['image/png','image/jpeg','image/webp'].includes(file.type)){setQrError('Choose a PNG, JPEG or WebP image.');return;}
  const BrowserDetector=(window as unknown as {BarcodeDetector?:new(options:{formats:string[]})=>{detect(source:ImageBitmap):Promise<Array<{rawValue:string}>>}}).BarcodeDetector;
  if(!BrowserDetector){setQrError('QR decoding is not supported in this browser. Paste the QR destination URL instead.');return;}
  try{const image=await createImageBitmap(file);try{const codes=await new BrowserDetector({formats:['qr_code']}).detect(image);if(!codes.length){setQrError('No QR code found. Try a clearer image.');return;}const destination=codes[0].rawValue;if(destination.length>8000){setQrError('The QR content is too long.');return;}setMode('link');setValue(destination);}finally{image.close();}}
  catch{setQrError('Could not read that image. Try a clearer image or paste the destination URL.');}
 }
 function choose(next:Mode){setMode(next);setResult(null);setError('');setValue('');}
 async function copyResult(){
  if(!result)return;
  const report=['Cyber Dragon — advisory check',`Risk level: ${result.risk_level}`,`Heuristic score: ${result.risk_score}/100`,...result.indicators.map(i=>'- '+i),result.recommendation,result.disclaimer].join('\n');
  try{await navigator.clipboard.writeText(report);setCopied(true);}catch{setError('Copy failed. You can select the results manually.');}
 }
 const severity=result?.risk_level==='high'?'high':result?.risk_level==='elevated'?'elevated':'unknown';
 return <main>
  <a href="#main-content" className="skip">Skip to content</a>
  <header className="nav wrap"><Link href="/" className="brand"><span className="brandmark" aria-hidden="true">🐉</span>CYBER<span>DRAGON</span></Link><nav aria-label="Main navigation"><a href="#shield">Check a threat</a><Link href="/learn">Safety academy</Link><a href="https://github.com/codesphere-u/cyber-dragon" target="_blank" rel="noopener noreferrer">GitHub ↗</a></nav></header>
  <section className="hero wrap" id="main-content"><div className="heroContent"><div className="eyebrow"><span className="pulse" aria-hidden="true"/> FREE DIGITAL SAFETY TOOLS · EARLY BETA</div><h1>Scams are getting smarter.<br/><em>So can you.</em></h1><p>Check suspicious messages, links and payment requests. Understand the warning signs and know what to do next — in plain language.</p><div className="heroActions"><a href="#shield" className="primary">Check something suspicious <span aria-hidden="true">↗</span></a><Link href="/learn" className="secondary">I need help now</Link></div><div className="trust"><span>✓ No signup</span><span>✓ Free to use</span><span>✓ No link visits</span></div></div><div className="heroVisual" aria-hidden="true"><div className="visualGlow"/><div className="visualShield"><span>◈</span><strong>DRAGON<br/>SHIELD</strong><small>KNOW BEFORE YOU ACT</small></div><div className="visualTag top">◉ EXPLAINABLE CHECKS</div><div className="visualTag bottom">✧ PRIVACY FIRST</div></div></section>
  <section className="scanner wrap" id="shield" aria-labelledby="shield-title"><div className="scannerHead"><div><span className="sectionTag">01 / DRAGON SHIELD</span><h2 id="shield-title">What would you like to check?</h2><p>Choose a category, paste the content and get an understandable assessment.</p></div><span className="status">● AVAILABLE NOW</span></div>
   <div className="modeGrid" role="group" aria-label="Check type">{modes.map(item=><button type="button" key={item.id} className={'modeCard '+(mode===item.id?'selected':'')} aria-pressed={mode===item.id} onClick={()=>choose(item.id)}><span className="modeIcon" aria-hidden="true">{item.icon}</span><span><strong>{item.title}</strong><small>{item.description}</small></span></button>)}</div>
   <div className="privacyToggle"><label><input type="checkbox" checked={privateMode} onChange={e=>setPrivateMode(e.target.checked)}/> <strong>Private on-device analysis</strong></label><span>{privateMode?'Your message stays in this browser. No scan request is sent to Cyber Dragon.':'Your text will be sent to the Cyber Dragon server for analysis.'}</span></div>
   {mode==='link'&&<div className="qrUpload"><label htmlFor="qr-image">Or scan a QR code from an image (supported browsers)</label><input id="qr-image" type="file" accept="image/png,image/jpeg,image/webp" onChange={e=>{const file=e.target.files?.[0];if(file)void decodeQr(file);e.target.value='';}}/><p>QR decoding happens on your device. Cyber Dragon does not open the destination.</p>{qrError&&<p role="alert">{qrError}</p>}</div>}
   <form onSubmit={submit}><div className="formTitle"><label htmlFor="threat">{mode==='link'?'Paste a website URL':mode==='payment'?'Paste a suspicious payment request':'Paste a suspicious message'}</label><button type="button" className="sample" onClick={()=>{setValue(samples[mode]);setResult(null);setError('');}}>Try an example</button></div><textarea id="threat" value={value} onChange={e=>setValue(e.target.value)} maxLength={8000} required rows={5} placeholder={mode==='link'?'https://example.com/suspicious-page':mode==='payment'?'Paste the payment message here...':'Paste an SMS, email or chat message here...'}/><div className="formBottom"><span>{value.length.toLocaleString()} / 8,000 characters</span><button type="submit" disabled={busy||!value.trim()}>{busy?'Checking…':'Analyze now →'}</button></div></form>
   <p className="privacy">🔒 Do not paste passwords, PINs, OTPs or personal data. Checks use limited rules; they cannot confirm whether something is safe. No submitted links are opened.</p>
   {error&&<div role="alert" className="error">{error}</div>}
   {result&&<div className={'result '+severity} role="status" aria-live="polite"><div className="resultTop"><div><span className="sectionTag">YOUR ASSESSMENT</span><h3>{severity==='high'?'High-risk warning signs':severity==='elevated'?'Warning signs detected':'No strong warning signs detected'}</h3><p className="resultSub">This is an automated heuristic assessment, not a verified threat verdict.</p></div><div className="score"><strong>{result.risk_score}</strong><small>/ 100</small></div></div><div className="resultBar" aria-hidden="true"><span style={{width:result.risk_score+'%'}}/></div><h4>What we noticed</h4>{result.indicators.length?<ul>{result.indicators.map((i,n)=><li key={n}>{i}</li>)}</ul>:<p>No matching patterns in this limited rule set. Sophisticated scams can still go undetected.</p>}<h4>What to do next</h4><p>{result.recommendation}</p><div className="resultActions"><button type="button" className="secondaryButton" onClick={copyResult}>{copied?'✓ Copied':'Copy assessment'}</button><Link href="/learn" className="secondary">Get safety guidance ↗</Link></div><small className="disclaimer">{result.disclaimer}</small></div>}
  </section>
  <section className="how wrap"><div><span className="sectionTag">02 / HOW TO STAY SAFER</span><h2>Three habits that protect everyone.</h2><p>Even without technical knowledge, these steps can reduce exposure to common scams.</p></div><div className="howGrid">{steps.map(s=><article className="howCard" key={s.number}><span>{s.number}</span><h3>{s.title}</h3><p>{s.text}</p></article>)}</div></section>
  <section className="helpBanner wrap"><div><span className="sectionTag">03 / DRAGON ACADEMY</span><h2>Already clicked, paid or shared a code?</h2><p>Find practical next steps for account takeovers, suspicious links, mobile-money fraud and impersonation.</p></div><Link href="/learn" className="primary">Open response guides ↗</Link></section>
  <section className="mission wrap"><div><span className="sectionTag">OPEN SOURCE · GLOBAL MISSION</span><h2>Digital safety should be for everyone.</h2><p>Designed for mobile-first communities and built in the open. Future improvements include reviewed translations, privacy-conscious threat intelligence and moderated community reporting.</p></div><a className="secondary" href="https://github.com/codesphere-u/cyber-dragon" target="_blank" rel="noopener noreferrer">Contribute on GitHub ↗</a></section>
  <footer className="footer wrap"><strong>🐉 CYBER DRAGON</strong><span>Defend. Educate. Empower.</span><span>Early beta · Advisory results only · Apache 2.0</span></footer>
 </main>;
}
