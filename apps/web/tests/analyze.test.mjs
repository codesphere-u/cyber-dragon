import test from 'node:test';
import assert from 'node:assert/strict';
import {
  analyzeText,
  redactSensitiveText,
  generateIncidentReport,
  THREAT_SCENARIOS,
} from '../lib/analyze.ts';

test('prize and credential request has warning indicators', () => {
  const result = analyzeText('URGENT! You won a prize. Send your OTP to claim it.');
  assert.equal(result.risk_level, 'high');
  assert.ok(result.indicators.length >= 2);
});

test('ordinary text is not falsely described as verified safe', () => {
  const result = analyzeText('See you at the office tomorrow.');
  assert.equal(result.risk_level, 'unknown_or_low_indicators');
  assert.match(result.recommendation, /does not establish safety/i);
});

test('numeric HTTP link with redirect is flagged without fetching', () => {
  const result = analyzeText('http://192.168.1.10/login?redirect=bank');
  assert.ok(result.risk_score >= 30);
  assert.ok(result.indicators.some((x) => x.includes('numeric IP')));
});

test('credential-bearing URL is flagged', () => {
  const result = analyzeText('https://alice:secret@example.com/');
  assert.ok(result.indicators.some((x) => x.includes('credentials')));
});

test('results do not echo sensitive input', () => {
  const secret = 'my-very-secret-token-123456';
  const result = analyzeText('Please check ' + secret);
  assert.equal(JSON.stringify(result).includes(secret), false);
});

test('score is bounded', () => {
  const result = analyzeText(
    'URGENT winner prize PIN OTP processing fee send money guaranteed profit https://192.168.1.10/?redirect=abc'
  );
  assert.ok(result.risk_score <= 100 && result.risk_score >= 0);
});

test('detects East African Mobile Money fake reversal and PIN lure', () => {
  const result = analyzeText(
    'I have wrongly sent UGX 350,000 to your MTN Mobile Money account by mistake. Enter your MoMo PIN to approve the reversal immediately.'
  );
  assert.equal(result.risk_level, 'high');
  assert.ok(result.category_scores.mobile_money_ussd_fraud >= 30);
  assert.ok(result.category_scores.credential_harvesting >= 35);
});

test('detects USSD *21* call and OTP diversion attack and recommends ##002#', () => {
  const result = analyzeText(
    'Urgent SIM notice: Dial *21*0772112233# now to keep your SIM active.'
  );
  assert.equal(result.risk_level, 'high');
  assert.ok(result.ussd_inspections.some((u) => u.pattern_type === 'call_or_sms_diversion_ussd'));
  assert.ok(result.safe_next_steps.some((s) => s.includes('##002#')));
});

test('detects brand-impersonation lookalike domains while allowing official brand domains', () => {
  const phish = analyzeText('Verify your account at https://stanbic-uganda-verify.top/login');
  assert.ok(phish.url_inspections[0].impersonated_brand === 'STANBIC');
  assert.ok(phish.category_scores.domain_url_deception >= 35);

  const official = analyzeText('Visit https://www.stanbicbank.co.ug for branch hours.');
  assert.equal(official.url_inspections[0].impersonated_brand, null);
  assert.equal(official.risk_score, 0);
});

test('detects Punycode IDN homograph domains', () => {
  const result = analyzeText('Check https://xn--pple-43d.com/security');
  assert.equal(result.url_inspections[0].is_punycode, true);
  assert.ok(result.indicators.some((i) => i.includes('Encoded internationalized domain')));
});

test('redacts phone numbers, PINs, emails, USSD codes, and URLs in incident reports', () => {
  const sample =
    'Call +256772998877 or email support@scam.example or dial *165*1*0772998877*50000# with PIN 4829 at https://mtn-claim.xyz/token?key=secret999';
  const redaction = redactSensitiveText(sample);
  assert.equal(redaction.redacted_text.includes('256772998877'), false);
  assert.equal(redaction.redacted_text.includes('4829'), false);
  assert.equal(redaction.redacted_text.includes('support@scam.example'), false);
  assert.equal(redaction.redacted_text.includes('secret999'), false);
  assert.ok(redaction.counts.phones_detected >= 1);
  assert.ok(redaction.counts.urls_detected >= 1);

  const report = generateIncidentReport(sample);
  assert.equal(report.markdown.includes('secret999'), false);
  assert.ok(report.markdown.includes('# Cyber Dragon — Privacy-Preserving Threat Advisory Report'));
});

test('all 8 curated threat benchmark scenarios match expected risk levels', () => {
  for (const scenario of THREAT_SCENARIOS) {
    const res = analyzeText(scenario.sample_text);
    assert.equal(
      res.risk_level,
      scenario.expected_level,
      `Scenario ${scenario.id} expected ${scenario.expected_level} but got ${res.risk_level} (score=${res.risk_score})`
    );
  }
});
