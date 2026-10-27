import { NextRequest, NextResponse } from 'next/server';
import { analyzeText } from '../../../lib/analyze';

export const runtime = 'nodejs';
const MAX_BYTES = 12_000;
const MAX_TEXT = 8_000;

export async function POST(request: NextRequest) {
  if (request.headers.get('content-type')?.split(';')[0]?.trim().toLowerCase() !== 'application/json') {
    return NextResponse.json({error:'Content-Type must be application/json.'},{status:415});
  }
  const length = Number(request.headers.get('content-length') || '0');
  if (!Number.isFinite(length) || length > MAX_BYTES) {
    return NextResponse.json({error:'Input is too large.'},{status:413});
  }
  let body: string;
  try {
    body = await request.text();
  } catch {
    return NextResponse.json({error:'Unable to read request.'},{status:400});
  }
  if (Buffer.byteLength(body,'utf8') > MAX_BYTES) {
    return NextResponse.json({error:'Input is too large.'},{status:413});
  }
  let payload: unknown;
  try {payload=JSON.parse(body);}catch{return NextResponse.json({error:'Invalid JSON.'},{status:400});}
  if (!payload || typeof payload !== 'object' || !('text' in payload) || typeof payload.text !== 'string' || !payload.text.trim() || payload.text.length > MAX_TEXT) {
    return NextResponse.json({error:'Enter a message or URL up to 8,000 characters.'},{status:400});
  }
  return NextResponse.json(analyzeText(payload.text),{headers:{'cache-control':'no-store, max-age=0'}});
}
