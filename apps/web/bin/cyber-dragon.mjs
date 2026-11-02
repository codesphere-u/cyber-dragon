#!/usr/bin/env -S node --experimental-strip-types
import { analyzeText, generateIncidentReport, redactSensitiveText, THREAT_SCENARIOS } from '../lib/analyze.ts';

function printHelp() {
  console.log(`🐉 Cyber Dragon CLI v1.0.0 — Open-Source Community Cyber Defense

Usage:
  cyber-dragon scan "<message or URL>" [--json]
  cyber-dragon report "<message or URL>" [--json]
  cyber-dragon redact "<message or URL>"
  cyber-dragon scenarios
  cyber-dragon benchmark [--json]

Safeguards:
  • Zero external network requests (SSRF-safe static & structural analysis)
  • Automatic PII & credential scrubbing in incident reports
  • Advisory heuristic scoring only (never guarantees safety)
`);
}

function runScan(text, asJson) {
  const result = analyzeText(text);
  if (asJson) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }
  console.log(`\n🐉 CYBER DRAGON THREAT ASSESSMENT`);
  console.log(`====================================================`);
  console.log(`Risk Score : ${result.risk_score} / 100 (${result.risk_level.toUpperCase()})`);
  console.log(`Confidence : ${result.confidence}`);
  console.log(`\nCategory Breakdown:`);
  for (const [cat, val] of Object.entries(result.category_scores)) {
    console.log(`  - ${cat.padEnd(30)}: ${val}/100`);
  }
  console.log(`\nTriggered Indicators (${result.indicators.length}):`);
  if (result.indicators.length === 0) {
    console.log(`  (none)`);
  } else {
    for (const ind of result.indicators) {
      console.log(`  • ${ind}`);
    }
  }
  if (result.url_inspections.length > 0) {
    console.log(`\nStructural URL Inspection (${result.url_inspections.length}):`);
    for (const u of result.url_inspections) {
      console.log(
        `  [${u.index}] ${u.scheme}://${u.registered_domain} | brand_lookalike=${u.impersonated_brand ?? 'none'} | punycode=${u.is_punycode} | ip=${u.is_ip_literal}`
      );
    }
  }
  console.log(`\nRecommended Next Steps:`);
  for (const step of result.safe_next_steps) {
    console.log(`  → ${step}`);
  }
  console.log(`\nDisclaimer: ${result.disclaimer}\n`);
}

function runBenchmark(asJson) {
  const results = THREAT_SCENARIOS.map((sc) => {
    const start = performance.now();
    const out = analyzeText(sc.sample_text);
    const elapsedMs = Number((performance.now() - start).toFixed(3));
    const matched = out.risk_level === sc.expected_level;
    return {
      id: sc.id,
      title: sc.title,
      expected_level: sc.expected_level,
      actual_level: out.risk_level,
      risk_score: out.risk_score,
      indicator_count: out.indicators.length,
      latency_ms: elapsedMs,
      passed: matched,
    };
  });

  const passedCount = results.filter((r) => r.passed).length;
  const avgLatencyMs = Number(
    (results.reduce((acc, r) => acc + r.latency_ms, 0) / results.length).toFixed(3)
  );

  const summary = {
    total_scenarios: results.length,
    passed_scenarios: passedCount,
    accuracy_pct: Number(((passedCount / results.length) * 100).toFixed(1)),
    avg_latency_ms: avgLatencyMs,
    results,
  };

  if (asJson) {
    console.log(JSON.stringify(summary, null, 2));
    return;
  }

  console.log(`\n🐉 CYBER DRAGON BENCHMARK SUITE (${summary.passed_scenarios}/${summary.total_scenarios} scenarios matched)`);
  console.log(`================================================================================`);
  for (const r of results) {
    const badge = r.passed ? 'PASS' : 'FAIL';
    console.log(
      `[${badge}] ${r.id.padEnd(24)} | score=${String(r.risk_score).padStart(3)}/100 | level=${r.actual_level.padEnd(25)} | ${r.latency_ms}ms`
    );
  }
  console.log(`================================================================================`);
  console.log(`Accuracy: ${summary.accuracy_pct}% | Average Heuristic Latency: ${summary.avg_latency_ms} ms\n`);
  if (passedCount !== results.length) {
    process.exitCode = 1;
  }
}

const args = process.argv.slice(2);
const command = args[0];
const asJson = args.includes('--json');
const textArg = args.find((a, idx) => idx > 0 && !a.startsWith('--')) ?? '';

if (!command || command === '--help' || command === '-h' || command === 'help') {
  printHelp();
} else if (command === 'scan') {
  if (!textArg.trim()) {
    console.error('Error: Provide a message or URL to scan.');
    process.exit(1);
  }
  runScan(textArg, asJson);
} else if (command === 'report') {
  if (!textArg.trim()) {
    console.error('Error: Provide a message or URL to generate an incident report.');
    process.exit(1);
  }
  const rep = generateIncidentReport(textArg);
  console.log(asJson ? JSON.stringify(rep, null, 2) : rep.markdown);
} else if (command === 'redact') {
  if (!textArg.trim()) {
    console.error('Error: Provide text to redact.');
    process.exit(1);
  }
  const red = redactSensitiveText(textArg);
  console.log(asJson ? JSON.stringify(red, null, 2) : red.redacted_text);
} else if (command === 'scenarios') {
  console.log(JSON.stringify(THREAT_SCENARIOS, null, 2));
} else if (command === 'benchmark') {
  runBenchmark(asJson);
} else {
  console.error(`Unknown command: ${command}`);
  printHelp();
  process.exit(1);
}
