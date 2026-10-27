import { NextRequest, NextResponse } from 'next/server';

export const runtime = 'nodejs';
export async function POST(request: NextRequest) {
  const length = Number(request.headers.get('content-length') || '0');
  if (length > 12_000) return NextResponse.json({ error: 'Input is too large.' }, { status: 413 });
  let payload: unknown;
  try { payload = await request.json(); } catch { return NextResponse.json({error: 'Invalid JSON.'}, {status: 400}); }
  if (!payload || typeof payload !== 'object' || !('text' in payload) || typeof payload.text !== 'string' || !payload.text.trim() || payload.text.length > 8000) {
    return NextResponse.json({error: 'Enter a message or URL up to 8,000 characters.'}, {status: 400});
  }
  const upstream = process.env.THREAT_API_URL;
  if (!upstream) return NextResponse.json({error: 'Scanner service is not configured.'}, {status: 503});
  try {
    const response = await fetch(new URL('/api/v1/analyze', upstream), {
      method: 'POST', headers: {'content-type': 'application/json'},
      body: JSON.stringify({text: payload.text}), cache: 'no-store',
      signal: AbortSignal.timeout(7000),
    });
    if (!response.ok) return NextResponse.json({error: 'Scanner unavailable. Please try again.'}, {status: 502});
    const data = await response.json();
    return NextResponse.json(data, {headers: {'cache-control': 'no-store'}});
  } catch {
    return NextResponse.json({error: 'Scanner unavailable. Please try again.'}, {status: 502});
  }
}
