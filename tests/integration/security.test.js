'use strict';
const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { startApp, ADMIN_USER, ADMIN_PASSWORD } = require('../helpers/app');
const { contosoDomain, PASSWORDS } = require('../helpers/directory');
const { createDomain, auditRows, setCookieLine } = require('../helpers/util');
const { Client } = require('../helpers/client');
const { TEST_JWT_SECRET } = require('../helpers/env');

const apps = [];
const boot = async (opts) => { const a = await startApp(opts); apps.push(a); return a; };
after(async () => { for (const a of apps) await a.stop().catch(() => {}); });

describe('cookie hardening', () => {
  it('COOKIE_SECURE=true marks every session cookie Secure', async () => {
    const app = await boot({ env: { COOKIE_SECURE: 'true' } });
    const admin = app.newAdminClient();
    const a = await admin.post('/api/admin/login', { username: ADMIN_USER, password: ADMIN_PASSWORD });
    assert.match(setCookieLine(a, 'admin_token'), /;\s*Secure/i);
    const adm = await app.adminSession();
    await createDomain(adm, contosoDomain());
    const u = await app.newUserClient().post('/api/auth/login', { username: 'helpdesk1@contoso.test', password: PASSWORDS.helpdesk1 });
    assert.match(setCookieLine(u, 'user_token'), /;\s*Secure/i);
  });
});

describe('brute-force protection (express-rate-limit on login endpoints)', () => {
  it('admin login: the Nth+1 attempt in the window gets 429, while other endpoints stay available', async () => {
    const app = await boot({ env: { AUTH_RATE_LIMIT_MAX: '3' } });
    const c = app.newAdminClient();
    const codes = [];
    for (let i = 0; i < 5; i++) codes.push((await c.post('/api/admin/login', { username: ADMIN_USER, password: `bad-${i}` })).status);
    assert.deepEqual(codes, [401, 401, 401, 429, 429]);
    assert.equal((await c.post('/api/admin/login', { username: ADMIN_USER, password: ADMIN_PASSWORD })).status, 429, 'even the right password is throttled');
    assert.equal((await c.get('/api/health')).status, 200);
    assert.equal((await c.get('/')).status, 200);
  });

  it('user login: throttled the same way, without affecting the admin portal', async () => {
    const app = await boot({ env: { AUTH_RATE_LIMIT_MAX: '3' } });
    const u = app.newUserClient();
    const codes = [];
    for (let i = 0; i < 5; i++) codes.push((await u.post('/api/auth/login', { username: 'a@nowhere.test', password: 'x' })).status);
    assert.deepEqual(codes, [401, 401, 401, 429, 429]);
    assert.equal((await app.adminSession()).jar.has('admin_token'), true);
  });

  it('authenticated admin API traffic is not rate limited (keep-alives must keep working)', async () => {
    const app = await boot({ env: { AUTH_RATE_LIMIT_MAX: '3' } });
    const admin = await app.adminSession();
    for (let i = 0; i < 15; i++) assert.equal((await admin.post('/api/admin/keepalive', {})).status, 200);
  });
});

describe('persistence and secret rotation across restarts', () => {
  it('bootstrap admin is created ONCE; changed bootstrap env vars do not reset the password', async () => {
    const first = await boot({});
    const dir = first.workDir;
    await first.stop({ keepFiles: true });
    const second = await boot({ workDir: dir, env: { ADMIN_BOOTSTRAP_PASSWORD: 'Different-Boot-Pass-1!' } });
    assert.equal((await second.newAdminClient().post('/api/admin/login', { username: ADMIN_USER, password: ADMIN_PASSWORD })).status, 200);
    assert.equal((await second.newAdminClient().post('/api/admin/login', { username: ADMIN_USER, password: 'Different-Boot-Pass-1!' })).status, 401);
    assert.equal((await second.adminSession()).jar.size, 1);
    assert.equal((await (await second.adminSession()).get('/api/admin/admins')).body.length, 1, 'no duplicate bootstrap admin');
  });

  it('configuration, secrets and audit history survive a restart, and live sessions keep working', async () => {
    const first = await boot({});
    const admin = await first.adminSession();
    const d = await createDomain(admin, contosoDomain());
    await admin.put('/api/admin/session-config', { userTimeoutMinutes: 45, adminTimeoutMinutes: 90 });
    await admin.put('/api/admin/alerts', { enabled: true, recipients: ['a@x.test'], smtp: { host: 'smtp.x.test', password: 'Persisted-Smtp-Pw!' } });
    const user = await first.userSession('helpdesk1@contoso.test', PASSWORDS.helpdesk1);
    const dir = first.workDir;
    await first.stop({ keepFiles: true });

    const second = await boot({ workDir: dir });
    const carry = (c, base) => { const n = new Client(base); n.jar = new Map(c.jar); return n; };
    const admin2 = carry(admin, second.adminUrl);
    const user2 = carry(user, second.userUrl);

    assert.equal((await admin2.get('/api/admin/me')).status, 200, 'admin session survives restart (same JWT_SECRET)');
    assert.ok((await admin2.get('/api/admin/domains')).body.some((x) => x.id === d.id));
    assert.equal((await admin2.get('/api/admin/session-config')).body.userTimeoutMinutes, 45);
    assert.equal((await admin2.get('/api/admin/alerts')).body.smtp.hasPassword, true);
    assert.ok((await auditRows(admin2, 'eventType=login&success=1')).length >= 1);
    assert.equal((await user2.get('/api/auth/me')).status, 200, 'user session survives restart');
    assert.equal((await user2.get('/api/users/search?q=normal')).status, 200, 'cached AD credentials still decrypt');
  });

  it('changing JWT_SECRET signs everybody out', async () => {
    const first = await boot({});
    const admin = await first.adminSession();
    const dir = first.workDir;
    await first.stop({ keepFiles: true });
    const second = await boot({ workDir: dir, env: { JWT_SECRET: 'a-brand-new-jwt-secret-value-0123456789' } });
    const n = new Client(second.adminUrl); n.jar = new Map(admin.jar);
    assert.equal((await n.get('/api/admin/me')).status, 401);
  });

  it('changing ENCRYPTION_KEY invalidates user sessions with a clear message and breaks stored secrets loudly (not silently)', async () => {
    const first = await boot({});
    const admin = await first.adminSession();
    await createDomain(admin, contosoDomain());
    const user = await first.userSession('helpdesk1@contoso.test', PASSWORDS.helpdesk1);
    const dir = first.workDir;
    await first.stop({ keepFiles: true });

    const second = await boot({ workDir: dir, env: { ENCRYPTION_KEY: 'rotated-encryption-key-0123456789abcdef' } });
    const n = new Client(second.userUrl); n.jar = new Map(user.jar);
    const r = await n.get('/api/users/search?q=normal');
    assert.equal(r.status, 401);
    assert.equal(r.body.error, 'Session invalid, please sign in again');
    // the server itself is still healthy and fresh sign-ins work
    assert.equal((await second.newUserClient().post('/api/auth/login', { username: 'helpdesk1@contoso.test', password: PASSWORDS.helpdesk1 })).status, 200);
  });

  it('a database created by an OLD schema is migrated in place on startup', async () => {
    const fs = require('fs'); const path = require('path'); const os = require('os');
    const Database = require('better-sqlite3');
    const work = fs.mkdtempSync(path.join(os.tmpdir(), 'iam-mig-'));
    fs.mkdirSync(path.join(work, 'data'), { recursive: true });
    const old = new Database(path.join(work, 'data', 'iam.db'));
    old.exec(`CREATE TABLE domains (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, domain_suffix TEXT UNIQUE NOT NULL,
      ldap_url TEXT NOT NULL, base_dn TEXT NOT NULL, bind_dn TEXT, bind_password_enc TEXT, tls_reject_unauthorized INTEGER NOT NULL DEFAULT 1,
      feature_unlock INTEGER NOT NULL DEFAULT 1, feature_reset INTEGER NOT NULL DEFAULT 1, feature_force_change INTEGER NOT NULL DEFAULT 1,
      enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
      INSERT INTO domains (name, domain_suffix, ldap_url, base_dn, created_at, updated_at) VALUES ('Legacy','legacy.test','ldaps://old-dc:636','DC=legacy,DC=test','t','t');`);
    old.close();
    const app = await boot({ workDir: work });
    const admin = await app.adminSession();
    const [d] = (await admin.get('/api/admin/domains')).body;
    assert.deepEqual(d.ldap_urls, ['ldaps://old-dc:636'], 'single ldap_url back-filled into ldap_urls');
    assert.deepEqual(d.allowed_groups, ['Domain Admins']);
    assert.equal(d.audit_enabled, true);
    assert.equal(d.alert_config.enabled, true);
    assert.equal(d.duo_config.mode, 'inherit');
  });
});

describe('resilience', () => {
  it('keeps serving after a burst of bad requests on both ports', async () => {
    const app = await boot({});
    const u = app.newUserClient(); const a = app.newAdminClient();
    const junk = ['{', '[]', 'null', '"str"', '{"username":1,"password":2}', '\u0000'];
    // Short timeout: a request the server never answers (see the known-gap test in user-auth) must not stall this test.
    const fire = (c, p, raw) => c.request('POST', p, { raw, headers: { 'content-type': 'application/json' }, timeoutMs: 1000 }).catch(() => null);
    for (const raw of junk) {
      await fire(u, '/api/auth/login', raw);
      await fire(a, '/api/admin/login', raw);
    }
    assert.equal((await u.get('/api/health')).status, 200);
    assert.equal((await a.get('/api/health')).status, 200);
    assert.ok(!/uncaught_exception/.test(app.output()), 'process hit an uncaught exception');
  });
});

describe('KNOWN GAPS (findings): these document security weaknesses found while testing', () => {
  // Each test below asserts the SAFE behaviour and is marked `todo`: a failing todo does not fail the
  // build, but shows up in the report. When the app is fixed the test starts passing - remove `todo`.

  it('logout should invalidate the session token server-side', { todo: 'JWTs are stateless: a copied cookie stays valid until expiry after logout' }, async () => {
    const app = await boot({});
    const admin = await app.adminSession();
    const stolen = admin.jar.get('admin_token');
    await admin.post('/api/admin/logout', {});
    const replay = await app.newAdminClient().get('/api/admin/domains', { headers: { cookie: `admin_token=${stolen}` } });
    assert.equal(replay.status, 401);
  });

  it('a deleted admin account should lose access immediately', { todo: 'requireAdminAuth never re-checks the admin_users table' }, async () => {
    const app = await boot({});
    const root = await app.adminSession();
    const made = await root.post('/api/admin/admins', { username: 'temp-admin', password: 'Temp-Admin-Pw-1!' });
    const temp = app.newAdminClient();
    await temp.post('/api/admin/login', { username: 'temp-admin', password: 'Temp-Admin-Pw-1!' });
    await root.del(`/api/admin/admins/${made.body.id}`);
    assert.equal((await temp.get('/api/admin/domains')).status, 401);
  });

  it('the audit log should not trust a client-supplied X-Forwarded-For when TRUST_PROXY is unset', { todo: 'audit.getClientIp() always trusts the first X-Forwarded-For hop, so IPs in the audit log / reports can be spoofed' }, async () => {
    const app = await boot({});
    await app.newUserClient().post('/api/auth/login', { username: 'x@nowhere.test', password: 'x' }, { headers: { 'x-forwarded-for': '6.6.6.6' } });
    const admin = await app.adminSession();
    const [row] = await auditRows(admin, 'eventType=login');
    assert.notEqual(row.ip_address, '6.6.6.6');
  });

  it('the app should refuse to run (or at least not accept forged sessions) with the built-in default JWT secret', { todo: 'JWT_SECRET falls back to a public hard-coded value with no warning' }, async () => {
    const app = await boot({ env: { JWT_SECRET: '' } });
    const forged = jwt.sign({ id: 1, username: ADMIN_USER, role: 'admin' }, 'insecure-dev-secret-change-me', { expiresIn: 600 });
    const r = await app.newAdminClient().get('/api/admin/domains', { headers: { cookie: `admin_token=${forged}` } });
    assert.equal(r.status, 401);
  });

  it('a stolen pending-MFA cookie should be single-use', { todo: 'mfa_pending is a stateless 5-minute JWT; the OAuth state is only compared, never recorded as consumed' }, async () => {
    const app = await boot({ duo: true });
    const admin = await app.adminSession();
    await admin.put('/api/admin/duo', { mode: 'enforced', clientId: 'DIABCDEFGHIJKLMNOPQR', clientSecret: 'S'.repeat(40), apiHostname: 'api-1234abcd.duosecurity.com', redirectUrl: 'https://x.test/cb' });
    await createDomain(admin, contosoDomain());
    const victim = app.newUserClient();
    const r = await victim.post('/api/auth/login', { username: 'helpdesk1@contoso.test', password: PASSWORDS.helpdesk1 });
    const state = new URL(r.body.redirectUrl).searchParams.get('state');
    const pending = victim.jar.get('mfa_pending');
    const url = `/api/auth/duo-callback?state=${state}&duo_code=good-code`;
    await victim.get(url);
    const attacker = app.newUserClient();
    const replay = await attacker.get(url, { headers: { cookie: `mfa_pending=${pending}` } });
    assert.equal(replay.headers.get('location'), '/?error=mfa_session_expired');
  });
});
