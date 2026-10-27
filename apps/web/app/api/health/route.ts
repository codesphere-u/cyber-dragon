import { NextResponse } from 'next/server';
export function GET(){return NextResponse.json({status:'ok',service:'cyber-dragon-web',version:'0.3.0'},{headers:{'cache-control':'no-store'}})}
