'use strict';
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('../helpers/app');
const pkg = require('../../package.json');

describe('server smoke: two isolated portals', () => {
  let app; let user; let admin;
  before(async () => { app = await startApp(); user = app.newUserClient(); admin = app.newAdminClient(); });
  after(() => app.stop());

  it('both portals report healthy and identify themselves', async () => {
    const u = await user.get('/api/health');
    const a = await admin.get('/api/health');
    assert.deepEqual(u.body, { ok: true, app: 'user' });
    assert.deepEqual(a.body, { ok: true, app: 'admin' });
  });

  it('exposes the package.json version on both portals', async () => {
    assert.deepEqual((await user.get('/api/version')).body, { version: pkg.version });
    assert.deepEqual((await admin.get('/api/version')).body, { version: pkg.version });
  });

  it('sets hardening headers (helmet) and hides the framework', async () => {
    const r = await user.get('/api/health');
    assert.equal(r.headers.get('x-powered-by'), null);
    assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
    assert.ok(r.headers.get('content-security-policy'), 'CSP header missing');
    assert.ok(r.headers.get('x-frame-options') || /frame-ancestors/.test(r.headers.get('content-security-policy')));
  });

  it('adds a unique 12-hex-char X-Request-Id to every response', async () => {
    const a = (await user.get('/api/health')).headers.get('x-request-id');
    const b = (await user.get('/api/health')).headers.get('x-request-id');
    assert.match(a, /^[0-9a-f]{12}$/);
    assert.notEqual(a, b);
  });

  it('serves the right single-page UI on each port', async () => {
    const u = await user.get('/');
    const a = await admin.get('/');
    assert.equal(u.status, 200);
    assert.equal(a.status, 200);
    assert.match(u.headers.get('content-type'), /text\/html/);
    assert.match(a.headers.get('content-type'), /text\/html/);
    assert.notEqual(u.text, a.text);
  });

  it('serves each portal\'s own static assets', async () => {
    for (const p of ['/css/style.css', '/js/theme.js', '/js/session.js', '/js/app.js']) assert.equal((await user.get(p)).status, 200, `user ${p}`);
    for (const p of ['/css/style.css', '/js/theme.js', '/js/session.js', '/js/admin.js']) assert.equal((await admin.get(p)).status, 200, `admin ${p}`);
    assert.match((await user.get('/js/app.js')).headers.get('content-type'), /javascript/);
    assert.match((await user.get('/css/style.css')).headers.get('content-type'), /text\/css/);
  });

  describe('port isolation: admin code does not exist on the user port and vice versa', () => {
    it('admin API is 404 on the user port', async () => {
      for (const p of ['/api/admin/domains', '/api/admin/login', '/api/admin/me']) {
        assert.equal((await user.get(p)).status, 404, p);
      }
      assert.equal((await user.post('/api/admin/login', { username: 'admin', password: 'x' })).status, 404);
    });

    it('user API is 404 on the admin port', async () => {
      for (const p of ['/api/auth/me', '/api/users/search?q=abc', '/api/users/audit']) {
        assert.equal((await admin.get(p)).status, 404, p);
      }
      assert.equal((await admin.post('/api/auth/login', { username: 'a@b.test', password: 'x' })).status, 404);
    });

    it('does not serve the other portal\'s UI or scripts', async () => {
      assert.equal((await user.get('/js/admin.js')).status, 404);
      assert.equal((await user.get('/admin.html')).status, 404);
      assert.equal((await admin.get('/js/app.js')).status, 404);
      assert.equal((await admin.get('/index.html')).status, 404);
    });
  });

  it('does not expose server internals or the data directory over HTTP', async () => {
    for (const p of ['/server.js', '/package.json', '/.env', '/data/iam.db', '/src/crypto.js', '/../server.js', '/%2e%2e/server.js']) {
      const u = await user.get(p); const a = await admin.get(p);
      assert.notEqual(u.status, 200, `user ${p}`);
      assert.notEqual(a.status, 200, `admin ${p}`);
    }
  });

  it('returns a JSON-free 404 for unknown routes without crashing', async () => {
    const r = await user.get('/api/nope');
    assert.equal(r.status, 404);
    assert.equal((await user.get('/api/health')).status, 200);
  });

  it('survives malformed JSON without leaking a stack trace or crashing', async () => {
    const r = await user.request('POST', '/api/auth/login', { raw: '{"username": ', headers: { 'content-type': 'application/json' } });
    assert.ok(r.status >= 400 && r.status < 600);
    assert.ok(!/SyntaxError|node_modules|\bat \w+/.test(r.text), `leaked internals: ${r.text}`);
    assert.equal((await user.get('/api/health')).status, 200);
  });

  it('survives an oversized JSON body (413 or similar), not a crash', async () => {
    const r = await admin.request('POST', '/api/admin/login', { raw: JSON.stringify({ username: 'a'.repeat(300000), password: 'x' }), headers: { 'content-type': 'application/json' } });
    assert.ok(r.status >= 400);
    assert.equal((await admin.get('/api/health')).status, 200);
  });
});
