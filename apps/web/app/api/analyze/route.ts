import { NextRequest, NextResponse } from 'next/server';

export const runtime = 'nodejs';
const LIMIT = 12_000;
function localAnalyze(text: string) {
  const rules: Array<[RegExp, number, string]> = [
    [/\b(?:pin|otp|one.time password|password|verification code)\b/i, 35, 'Requests or mentions sensitive authentication information'],
    [/\b(?:won|winner|prize|lottery|giveaway|congratulations)\b/i, 20, 'Prize or reward language'],
    [/\b(?:urgent|immediately|act now|within 24 hours|account suspended)\b/i, 15, 'Urgency or pressure language'],
    [/\b(?:send money|processing fee|advance fee|pay to claim)\b/i, 30, 'Upfront payment request'],
    [/\b(?:mobile money|momo|mtn|airtel money)\b/i, 10, 'Mobile-money context; verify requests through official channels'],
  ];
  const indicators: string[] = [];
  let score = 0;
  for (const [pattern, weight, reason] of rules) if (pattern.test(text)) {score += weight; indicators.push(reason);}
  for (const match of text.match(/https?:\/\/[^\s<>"']+/gi)?.slice(0, 10) ?? []) {
    try {
      const host = new URL(match.replace(/[.,!?)]+$/, '')).hostname;
      if (host.startsWith('xn--') || host.includes('.xn--')) {score += 25; indicators.push('Internationalized domain encoding; inspect destination carefully');}
      if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) {score += 20; indicators.push('Link uses a numeric IP address');}
    } catch {score += 10; indicators.push('Malformed URL; do not open untrusted links');}
  }
  score = Math.min(score, 100);
  return {
    risk_score: score,
    risk_level: score >= 60 ? 'high' : score >= 30 ? 'elevated' : 'unknown_or_low_indicators',
    indicators: [...new Set(indicators)],
    recommendation: score >= 30 ? 'Do not share passwords, PINs or OTPs. Verify unexpected requests through official channels.' : 'No strong heuristic indicators found. This does not establish safety; verify the source independently.',
    disclaimer: 'Heuristic assessment only; no live reputation check, AI inference, or guarantee of safety. Content is not stored by this service.',
  };
}
export async function POST(request: NextRequest) {
  const length = Number(request.headers.get('content-length') || '0');
  if (length > LIMIT) return NextResponse.json({error:'Input is too large.'},{status:413});
  let payload: unknown;
  try { payload = await request.json(); } catch {return NextResponse.json({error:'Invalid JSON.'},{status:400});}
  if (!payload || typeof payload !== 'object' || !('text' in payload) || typeof payload.text !== 'string' || !payload.text.trim() || payload.text.length > 8000) {
    return NextResponse.json({error:'Enter a message or URL up to 8,000 characters.'},{status:400});
  }
  const text = payload.text;
  const upstream = process.env.THREAT_API_URL;
  if (upstream) {
    try {
      const response = await fetch(new URL('/api/v1/analyze', upstream), {
        method:'POST', headers:{'content-type':'application/json'},
        body:JSON.stringify({text}), cache:'no-store', signal:AbortSignal.timeout(7000),
      });
      if (response.ok) return NextResponse.json(await response.json(),{headers:{'cache-control':'no-store'}});
    } catch { /* Continue with local heuristic fallback. */ }
  }
  return NextResponse.json(localAnalyze(text),{headers:{'cache-control':'no-store'}});
}
