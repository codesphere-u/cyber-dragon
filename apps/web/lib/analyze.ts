export type ScanResult = {risk_score:number;risk_level:string;indicators:string[];recommendation:string;disclaimer:string};
const RULES: Array<[RegExp, number, string]> = [
  [/\b(?:pin|otp|one.time password|password|verification code)\b/i,35,'Authentication codes or credentials mentioned'],
  [/\b(?:won|winner|prize|lottery|giveaway|congratulations)\b/i,20,'Prize or reward language'],
  [/\b(?:urgent|immediately|act now|within 24 hours|account suspended)\b/i,15,'Urgency or pressure language'],
  [/\b(?:send money|processing fee|advance fee|pay to claim)\b/i,30,'Upfront payment request'],
  [/\b(?:mobile money|momo|mtn|airtel money)\b/i,10,'Mobile-money context'],
  [/\b(?:investment returns|guaranteed profit|double your money)\b/i,25,'Unrealistic financial promise'],
  [/\b(?:verify your account|confirm your identity|unlock your account)\b/i,15,'Account verification or unlock request'],
];
export function analyzeText(text:string):ScanResult {
  let score=0; const indicators:string[]=[];
  for(const [pattern,weight,reason] of RULES){if(pattern.test(text)){score+=weight;indicators.push(reason);}}
  const urls=text.match(/https?:\/\/[^\s<>"']+/gi)?.slice(0,10) ?? [];
  for(const raw of urls){
    try{
      const url=new URL(raw.replace(/[.,!?)]+$/,''));
      const host=url.hostname.toLowerCase();
      if(url.username||url.password){score+=35;indicators.push('Link embeds credentials in its address');}
      if(host.startsWith('xn--')||host.includes('.xn--')){score+=25;indicators.push('Encoded internationalized domain; inspect spelling');}
      if(/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)){score+=20;indicators.push('Link uses a numeric IP address');}
      if(url.protocol==='http:'){score+=10;indicators.push('Unencrypted HTTP link');}
      if(host.split('.').length>5){score+=10;indicators.push('Unusually deep subdomain structure');}
      if(url.pathname.length>160){score+=10;indicators.push('Unusually long URL path');}
      if(url.searchParams.has('redirect')||url.searchParams.has('url')){score+=10;indicators.push('Link includes a redirect parameter');}
    }catch{score+=10;indicators.push('Malformed link');}
  }
  score=Math.min(100,score);
  return {
    risk_score:score,
    risk_level:score>=60?'high':score>=30?'elevated':'unknown_or_low_indicators',
    indicators:[...new Set(indicators)],
    recommendation:score>=30?'Do not share PINs, OTPs or passwords. Verify unexpected requests using independently obtained official contact details.':'No strong heuristic indicators found. This does not establish safety; verify the source independently.',
    disclaimer:'Heuristic assessment only. No website was visited, no reputation lookup was performed, and no safety guarantee is implied.',
  };
}
