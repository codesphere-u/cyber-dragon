import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeText } from '../lib/analyze.ts';

test('prize and credential request has warning indicators',()=>{
 const result=analyzeText('URGENT! You won a prize. Send your OTP to claim it.');
 assert.equal(result.risk_level,'high');
 assert.ok(result.indicators.length>=2);
});
test('ordinary text is not falsely described as verified safe',()=>{
 const result=analyzeText('See you at the office tomorrow.');
 assert.equal(result.risk_level,'unknown_or_low_indicators');
 assert.match(result.recommendation,/does not establish safety/i);
});
test('numeric HTTP link with redirect is flagged without fetching',()=>{
 const result=analyzeText('http://192.168.1.10/login?redirect=bank');
 assert.ok(result.risk_score>=30);
 assert.ok(result.indicators.some(x=>x.includes('numeric IP')));
});
test('credential-bearing URL is flagged',()=>{
 const result=analyzeText('https://alice:secret@example.com/');
 assert.ok(result.indicators.some(x=>x.includes('credentials')));
});
test('results do not echo sensitive input',()=>{
 const secret='my-very-secret-token-123456';
 const result=analyzeText('Please check '+secret);
 assert.equal(JSON.stringify(result).includes(secret),false);
});
test('score is bounded',()=>{
 const result=analyzeText('URGENT winner prize PIN OTP processing fee send money guaranteed profit https://192.168.1.10/?redirect=abc');
 assert.ok(result.risk_score<=100&&result.risk_score>=0);
});
