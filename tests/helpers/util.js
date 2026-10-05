'use strict';
const assert = require('node:assert/strict');

let counter = 0;
const uniqueSuffix = (prefix = 'dom') => `${prefix}${Date.now().toString(36)}${counter++}.test`;

/** POST a domain as an admin and return the created domain (asserts HTTP 200). */
async function createDomain(admin, payload) {
  const r = await admin.post('/api/admin/domains', payload);
  assert.equal(r.status, 200, `createDomain failed: ${r.text}`);
  return r.body;
}

/** Fetch up to 100 audit rows (newest first) with optional extra query string, e.g. "eventType=login". */
async function auditRows(admin, qs = '') {
  const r = await admin.get(`/api/admin/audit?pageSize=100${qs ? `&${qs}` : ''}`);
  assert.equal(r.status, 200, r.text);
  return r.body.rows;
}

/** Decode (NOT verify) a JWT payload. */
function decodeJwt(token) {
  return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
}

/** Pick one Set-Cookie header line by cookie name. */
function setCookieLine(res, name) {
  return res.setCookie.find((c) => c.startsWith(`${name}=`));
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Poll `fn` until it returns truthy or the timeout elapses. */
async function eventually(fn, { timeoutMs = 5000, intervalMs = 50, message = 'condition' } = {}) {
  const started = Date.now();
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() - started > timeoutMs) throw new Error(`Timed out waiting for ${message}`);
    await sleep(intervalMs);
  }
}

module.exports = { uniqueSuffix, createDomain, auditRows, decodeJwt, setCookieLine, sleep, eventually };
