'use strict';
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { startApp, ADMIN_USER, ADMIN_PASSWORD } = require('../helpers/app');
const { TEST_JWT_SECRET } = require('../helpers/env');
const { setCookieLine } = require('../helpers/util');

describe('admin portal authentication', () => {
  let app;
  before(async () => { app = await startApp(); });
  after(() => app.stop());

  describe('login', () => {
    it('rejects missing credentials with 400', async () => {
      const c = app.newAdminClient();
      assert.equal((await c.post('/api/admin/login', {})).status, 400);
      assert.equal((await c.post('/api/admin/login', { username: ADMIN_USER })).status, 400);
      assert.equal((await c.post('/api/admin/login', { password: 'x' })).status, 400);
    });

    it('rejects a wrong password and an unknown user with the same 401 message (no user enumeration)', async () => {
      const c = app.newAdminClient();
      const wrong = await c.post('/api/admin/login', { username: ADMIN_USER, password: 'nope' });
      const unknown = await c.post('/api/admin/login', { username: 'ghost', password: 'nope' });
      assert.equal(wrong.status, 401);
      assert.equal(unknown.status, 401);
      assert.deepEqual(wrong.body, unknown.body);
      assert.equal(wrong.body.error, 'Invalid credentials');
      assert.equal(c.jar.size, 0, 'no cookie on failure');
    });

    it('resists SQL injection in the username', async () => {
      const c = app.newAdminClient();
      for (const u of ["' OR '1'='1", "admin' --", "admin'; DROP TABLE admin_users; --"]) {
        assert.equal((await c.post('/api/admin/login', { username: u, password: "' OR '1'='1" })).status, 401, u);
      }
      assert.equal((await app.adminSession()).jar.size, 1, 'admin table still intact');
    });

    it('rejects non-string credential types without a 500', async () => {
      const c = app.newAdminClient();
      for (const body of [{ username: { $ne: null }, password: { $ne: null } }, { username: ['admin'], password: ['x'] }]) {
        const r = await c.post('/api/admin/login', body);
        assert.ok(r.status >= 400, `must not authenticate, got ${r.status}`);
      }
    });

    it('succeeds with the bootstrap admin and returns session info', async () => {
      const c = app.newAdminClient();
      const r = await c.post('/api/admin/login', { username: ADMIN_USER, password: ADMIN_PASSWORD });
      assert.equal(r.status, 200);
      assert.equal(r.body.ok, true);
      assert.equal(r.body.username, ADMIN_USER);
      assert.equal(r.body.sessionTimeoutSeconds, 480 * 60);
      assert.equal(r.body.theme, null);
    });

    it('issues an httpOnly, SameSite=Strict cookie (not Secure when COOKIE_SECURE=false)', async () => {
      const r = await app.newAdminClient().post('/api/admin/login', { username: ADMIN_USER, password: ADMIN_PASSWORD });
      const line = setCookieLine(r, 'admin_token');
      assert.ok(line, 'admin_token cookie missing');
      assert.match(line, /HttpOnly/i);
      assert.match(line, /SameSite=Strict/i);
      assert.doesNotMatch(line, /;\s*Secure/i);
    });

    it('never returns the password hash or token in the JSON body', async () => {
      const r = await app.newAdminClient().post('/api/admin/login', { username: ADMIN_USER, password: ADMIN_PASSWORD });
      assert.ok(!/hash|token|\$2[aby]\$/i.test(r.text), r.text);
    });
  });

  describe('session', () => {
    it('/me returns the current admin and refreshes the sliding session', async () => {
      const c = await app.adminSession();
      const r = await c.get('/api/admin/me');
      assert.equal(r.status, 200);
      assert.equal(r.body.username, ADMIN_USER);
      assert.ok(setCookieLine(r, 'admin_token'), 'cookie re-issued');
      assert.equal(r.headers.get('x-session-timeout'), String(480 * 60));
    });

    it('every authenticated API call advertises the session timeout', async () => {
      const c = await app.adminSession();
      const r = await c.get('/api/admin/domains');
      assert.equal(r.headers.get('x-session-timeout'), String(480 * 60));
    });

    it('/me is 401 without a cookie', async () => {
      assert.equal((await app.newAdminClient().get('/api/admin/me')).status, 401);
    });

    it('logout clears the cookie', async () => {
      const c = await app.adminSession();
      assert.equal((await c.post('/api/admin/logout', {})).body.ok, true);
      assert.equal((await c.get('/api/admin/me')).status, 401);
    });
  });

  describe('every admin endpoint requires authentication', () => {
    const GETS = ['/domains', '/settings', '/session-config', '/alerts', '/duo', '/audit', '/audit/export', '/audit-retention',
      '/admins', '/templates', '/templates-dir', '/preferences', '/reports/summary', '/reports/failed-logins', '/reports/by-user/export'];
    for (const p of GETS) {
      it(`GET /api/admin${p} -> 401`, async () => {
        const r = await app.newAdminClient().get(`/api/admin${p}`);
        assert.equal(r.status, 401);
        assert.equal(r.body.error, 'Not authenticated');
      });
    }

    const WRITES = [
      ['POST', '/domains'], ['PUT', '/domains/1'], ['DELETE', '/domains/1'], ['POST', '/test-connection'], ['POST', '/test-lookup'],
      ['PUT', '/settings'], ['PUT', '/session-config'], ['POST', '/keepalive'], ['PUT', '/alerts'], ['POST', '/alerts/test'],
      ['PUT', '/preferences'], ['PUT', '/duo'], ['POST', '/duo/test'], ['PUT', '/audit-retention'],
      ['POST', '/admins'], ['PUT', '/admins/1/password'], ['DELETE', '/admins/1'],
      ['PUT', '/templates/login_failure'], ['DELETE', '/templates/login_failure'], ['POST', '/templates/login_failure/preview'],
    ];
    for (const [m, p] of WRITES) {
      it(`${m} /api/admin${p} -> 401`, async () => {
        assert.equal((await app.newAdminClient().request(m, `/api/admin${p}`, { json: {} })).status, 401);
      });
    }
  });

  describe('token forgery and role confusion', () => {
    const asCookie = (token) => ({ headers: { cookie: `admin_token=${token}` } });
    const payload = { id: 1, username: ADMIN_USER };

    it('rejects a token signed with the wrong secret', async () => {
      const t = jwt.sign({ ...payload, role: 'admin' }, 'wrong-secret', { expiresIn: 600 });
      assert.equal((await app.newAdminClient().get('/api/admin/me', asCookie(t))).status, 401);
      assert.equal((await app.newAdminClient().get('/api/admin/domains', asCookie(t))).status, 401);
    });

    it('rejects an expired token', async () => {
      const t = jwt.sign({ ...payload, role: 'admin' }, TEST_JWT_SECRET, { expiresIn: -60 });
      assert.equal((await app.newAdminClient().get('/api/admin/domains', asCookie(t))).status, 401);
    });

    it('rejects a correctly signed token whose role is not "admin" (user / mfa_pending tokens)', async () => {
      for (const role of ['user', 'mfa_pending', undefined, 'superuser']) {
        const t = jwt.sign({ ...payload, ...(role ? { role } : {}) }, TEST_JWT_SECRET, { expiresIn: 600 });
        assert.equal((await app.newAdminClient().get('/api/admin/domains', asCookie(t))).status, 401, `role=${role}`);
      }
    });

    it('rejects an unsigned (alg=none) token', async () => {
      const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
      const t = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ ...payload, role: 'admin', exp: Math.floor(Date.now() / 1000) + 600 })}.`;
      assert.equal((await app.newAdminClient().get('/api/admin/domains', asCookie(t))).status, 401);
    });

    it('rejects a tampered payload that keeps the original signature', async () => {
      const good = (await (async () => { const c = await app.adminSession(); return c.jar.get('admin_token'); })());
      const [h, , s] = good.split('.');
      const evil = Buffer.from(JSON.stringify({ id: 99, username: 'evil', role: 'admin', exp: Math.floor(Date.now() / 1000) + 600 })).toString('base64url');
      assert.equal((await app.newAdminClient().get('/api/admin/domains', asCookie(`${h}.${evil}.${s}`))).status, 401);
    });

    it('ignores the token if sent as a header or query string instead of the cookie', async () => {
      const c = await app.adminSession();
      const tok = c.jar.get('admin_token');
      const r1 = await app.newAdminClient().get('/api/admin/domains', { headers: { authorization: `Bearer ${tok}` } });
      const r2 = await app.newAdminClient().get(`/api/admin/domains?admin_token=${tok}`);
      assert.equal(r1.status, 401);
      assert.equal(r2.status, 401);
    });
  });
});
