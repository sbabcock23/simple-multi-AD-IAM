#!/usr/bin/env node
'use strict';
/**
 * Test runner:  node tests/run.js [unit|integration|all] [name-filter]
 *
 * Wraps node:test (no extra dependencies, Node >= 20) to
 *   - find test files without relying on shell globbing (works on Windows too),
 *   - print the normal "spec" report,
 *   - finish with a short summary that lists the KNOWN-GAP findings (tests marked `todo`),
 *   - write that summary to the GitHub Actions job summary when running in CI,
 *   - exit non-zero if any non-todo test fails.
 */
const fs = require('fs');
const path = require('path');
const { run } = require('node:test');
const { spec } = require('node:test/reporters');

const group = process.argv[2] || 'all';
const nameFilter = process.argv[3];
const dirs = { unit: ['unit'], integration: ['integration'], all: ['unit', 'integration'] }[group];
if (!dirs) { console.error('usage: node tests/run.js [unit|integration|all] [name-filter]'); process.exit(2); }

const files = dirs.flatMap((d) => fs.readdirSync(path.join(__dirname, d))
  .filter((f) => f.endsWith('.test.js')).sort().map((f) => path.join(__dirname, d, f)));

const totals = {};
const openFindings = [];
const fixedFindings = [];
let hardFailures = 0;

const stream = run({
  files,
  timeout: 120000,
  ...(nameFilter ? { testNamePatterns: [nameFilter] } : {}),
});

stream.on('test:diagnostic', (d) => {
  const m = /^(tests|suites|pass|fail|cancelled|skipped|todo) (\d+)$/.exec(d.message);
  if (m) totals[m[1]] = (totals[m[1]] || 0) + Number(m[2]);
});
stream.on('test:fail', (d) => {
  if (d.todo) openFindings.push({ name: d.name, why: typeof d.todo === 'string' ? d.todo : '' });
  else hardFailures++;
});
stream.on('test:pass', (d) => {
  if (d.todo && d.details && d.details.type !== 'suite') fixedFindings.push(d.name);
});

stream.compose(spec).pipe(process.stdout);

stream.on('close', () => {
  const lines = [];
  lines.push('## IAM test results', '');
  lines.push(`| files | tests | passed | failed | known gaps (todo) |`, `|---|---|---|---|---|`);
  lines.push(`| ${files.length} | ${totals.tests || 0} | ${totals.pass || 0} | ${totals.fail || 0} | ${totals.todo || 0} |`, '');
  if (openFindings.length) {
    lines.push('### Known gaps still present (do not fail the build)', '');
    openFindings.forEach((f) => lines.push(`- **${f.name}**${f.why ? ` — ${f.why}` : ''}`));
    lines.push('');
  }
  if (fixedFindings.length) {
    lines.push('### Known gaps that now PASS - remove their `todo` marker', '');
    fixedFindings.forEach((n) => lines.push(`- ${n}`));
    lines.push('');
  }
  const text = lines.join('\n');
  console.log(`\n${text}`);
  if (process.env.GITHUB_STEP_SUMMARY) {
    try { fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${text}\n`); } catch (e) { /* non-fatal */ }
  }
  process.exitCode = hardFailures || (totals.fail || 0) ? 1 : 0;
});
