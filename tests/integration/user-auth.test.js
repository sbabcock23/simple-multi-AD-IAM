'use strict';
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { startApp, ADMIN_PASSWORD } = require('../helpers/app');
const { contosoDomain, fabrikamDomain, PASSWORDS } = require('../helpers/directory');
const { TEST_JWT_SECRET } = require('../helpers/env');
const { createDomain, auditRows, decodeJwt, setCookieLine } = require('../helpers/util');

const GENERIC = 'Invalid username or password, or your account is not authorized to use this portal.';

describe('user portal: sign-in against (fake) Active Directory', () => {
  let app; let admin; let contoso;
  before(async () => {
    app = await startApp();
    admin = await app.adminSession();
    contoso = await createDomain(admin, contosoDomain());
    await createDomain(admin, fabrikamDomain());
  });
  after(() => app.stop());

  const login = (username, password) => app.newUserClient().post('/api/auth/login', { username, password });

  describe('input validation', () => {
    it('requires username@domain and a password', async () => {
      for (const body of [{}, { username: 'helpdesk1@contoso.test' }, { password: 'x' }, { username: 'helpdesk1', password: 'x' }]) {
        const r = await app.newUserClient().post('/api/auth/login', body);
        assert.equal(r.status, 400, JSON.stringify(body));
        assert.equal(r.body.error, 'Enter your username as username@domain');
      }
    });

    it('never authenticates when credentials are objects/arrays instead of strings', async () => {
      for (const body of [{ username: { $ne: 1 }, password: { $ne: 1 } }, { username: ['a@contoso.test'], password: ['x'] }, { username: 5, password: 5 }]) {
        const c = app.newUserClient();
        const r = await c.post('/api/auth/login', body, { timeoutMs: 1500 }).catch((e) => ({ status: 'no-response', err: e.name }));
        assert.notEqual(r.status, 200, JSON.stringify(body));
        assert.equal(c.jar.has('user_token'), false, 'no session may be issued');
      }
      assert.equal((await app.newUserClient().get('/api/health')).status, 200, 'server still healthy');
    });

    // KNOWN GAP (finding): the async login handler calls username.includes() on whatever JSON type it was
    // sent. Under Express 4 a rejected async handler is never routed to the error handler, so the request
    // is left hanging until the client gives up (one stuck connection per request).
    it('answers non-string credentials promptly with a 4xx instead of leaving the request hanging', { todo: 'POST /api/auth/login with {"username":{}} never gets a response (async handler rejection under Express 4)' }, async () => {
      const r = await app.newUserClient().post('/api/auth/login', { username: { a: 1 }, password: 'x' }, { timeoutMs: 2000 });
      assert.ok(r.status >= 400 && r.status < 500, `got ${r.status}`);
    });
  });

  describe('successful sign-in', () => {
    it('signs in by UPN and returns the session description', async () => {
      const c = app.newUserClient();
      const r = await c.post('/api/auth/login', { username: 'helpdesk1@contoso.test', password: PASSWORDS.helpdesk1 });
      assert.equal(r.status, 200);
      assert.deepEqual(r.body, {
        ok: true, username: 'helpdesk1@contoso.test', domain: 'Contoso',
        features: { unlock: true, reset: true, forceChange: true }, sessionTimeoutSeconds: 7200, theme: null,
      });
    });

    it('issues an httpOnly, SameSite=Strict cookie', async () => {
      const r = await login('helpdesk1@contoso.test', PASSWORDS.helpdesk1);
      const line = setCookieLine(r, 'user_token');
      assert.match(line, /HttpOnly/i);
      assert.match(line, /SameSite=Strict/i);
      assert.doesNotMatch(line, /;\s*Secure/i);
    });

    it('never puts the AD password in plaintext inside the session cookie', async () => {
      const c = app.newUserClient();
      await c.post('/api/auth/login', { username: 'helpdesk1@contoso.test', password: PASSWORDS.helpdesk1 });
      const token = c.jar.get('user_token');
      const payload = decodeJwt(token);
      assert.ok(!token.includes(PASSWORDS.helpdesk1));
      assert.ok(payload.pwd && payload.pwd !== PASSWORDS.helpdesk1, 'password must be stored encrypted');
      assert.ok(!Buffer.from(payload.pwd, 'base64').toString('utf8').includes(PASSWORDS.helpdesk1));
      assert.equal(payload.role, 'user');
      assert.match(payload.bindDn, /^CN=Help Desk One,/);
    });

    it('treats the domain suffix case-insensitively', async () => {
      const r = await login('HELPDESK1@CONTOSO.TEST', PASSWORDS.helpdesk1);
      assert.equal(r.status, 200);
      assert.equal(r.body.domain, 'Contoso');
    });

    it('authorises members of a nested group', async () => {
      assert.equal((await login('nested1@contoso.test', PASSWORDS.nested1)).status, 200);
    });

    it('falls back to NETBIOS\\sAMAccountName when the typed UPN differs from the real one', async () => {
      const r = await login('legacy1@contoso.test', PASSWORDS.legacy1);
      assert.equal(r.status, 200);
      assert.ok(app.ldapLog().some((e) => e.op === 'bind' && e.identity === 'CONTOSO\\legacy1' && e.ok));
    });

    it('signs in by e-mail address through the domain\'s lookup account', async () => {
      const r = await login('amy@fabrikam.com', PASSWORDS.amy);
      assert.equal(r.status, 200);
      assert.equal(r.body.domain, 'Fabrikam');
      const log = app.ldapLog();
      assert.ok(log.some((e) => e.op === 'bind' && e.identity.startsWith('CN=svc-lookup') && e.ok), 'lookup account was used');
    });

    it('subsequent directory work binds with the resolved DN, not what the user typed', async () => {
      const c = app.newUserClient();
      await c.post('/api/auth/login', { username: 'amy@fabrikam.com', password: PASSWORDS.amy });
      const before = app.ldapLog().length;
      const r = await c.get('/api/users/search?q=bob');
      assert.equal(r.status, 200);
      const binds = app.ldapLog().slice(before).filter((e) => e.op === 'bind');
      assert.ok(binds.length >= 1 && binds.every((b) => b.identity === 'CN=Amy Support,OU=Users,DC=fabrikam,DC=test'));
    });

    it('fails over to the second LDAP server when the first is down', async () => {
      await createDomain(admin, contosoDomain({ name: 'Failover', domain_suffix: 'failover.test', ldap_urls: ['ldaps://dead.contoso.test:636', 'ldaps://dc2.contoso.test:636'] }));
      const r = await login('helpdesk1@failover.test', PASSWORDS.helpdesk1);
      assert.equal(r.status, 200);
      const urls = app.ldapLog().filter((e) => e.op === 'connect').map((e) => e.url);
      assert.ok(urls.includes('ldaps://dead.contoso.test:636'));
    });
  });

  describe('rejections', () => {
    it('unknown domain -> 401 with its own message, and an audit record', async () => {
      const r = await login('ghost@nowhere.test', 'whatever');
      assert.equal(r.status, 401);
      assert.equal(r.body.error, 'That domain is not configured for self-service access');
      const [row] = await auditRows(admin, 'eventType=login&success=0');
      assert.equal(row.actor_username, 'ghost@nowhere.test');
      assert.equal(row.domain_id, null);
      assert.equal(row.detail, 'Domain not configured for self-service access');
    });

    it('a disabled domain cannot be signed in to', async () => {
      await createDomain(admin, contosoDomain({ name: 'Off', domain_suffix: 'off.test', enabled: false }));
      const r = await login('helpdesk1@off.test', PASSWORDS.helpdesk1);
      assert.equal(r.status, 401);
      assert.match(r.body.error, /not configured/);
    });

    it('wrong password, non-member, locked and disabled accounts all get the SAME generic message', async () => {
      const cases = [
        ['wrong password', 'helpdesk1@contoso.test', 'not-the-password'],
        ['not in an allowed group', 'outsider1@contoso.test', PASSWORDS.outsider1],
        ['unknown account', 'nobody@contoso.test', 'whatever'],
        ['locked account', 'locked.user@contoso.test', 'Whatever1!'],
        ['disabled account', 'disabled.user@contoso.test', 'Whatever3!'],
      ];
      for (const [label, u, p] of cases) {
        const c = app.newUserClient();
        const r = await c.post('/api/auth/login', { username: u, password: p });
        assert.equal(r.status, 401, label);
        assert.equal(r.body.error, GENERIC, label);
        assert.equal(c.jar.has('user_token'), false, `${label}: no session cookie`);
      }
    });

    it('records the specific (internal) reason in the audit log', async () => {
      await login('helpdesk1@contoso.test', 'bad-password-1');
      let [row] = await auditRows(admin, 'eventType=login&success=0');
      assert.equal(row.detail, 'invalid_credentials_or_unreachable');
      await login('outsider1@contoso.test', PASSWORDS.outsider1);
      [row] = await auditRows(admin, 'eventType=login&success=0');
      assert.equal(row.detail, 'not_a_member_of_an_allowed_group');
      assert.equal(row.domain_label, 'Contoso');
    });

    it('fails closed when none of the configured allowed groups exist', async () => {
      await createDomain(admin, contosoDomain({ name: 'Ghost', domain_suffix: 'ghostgroup.test', allowed_groups: ['No Such Group'] }));
      const r = await login('helpdesk1@ghostgroup.test', PASSWORDS.helpdesk1);
      assert.equal(r.status, 401);
      assert.equal(r.body.error, GENERIC);
      const [row] = await auditRows(admin, 'eventType=login&success=0');
      assert.equal(row.detail, 'no_allowed_groups_configured');
    });

    it('returns the generic 401 (not a 500) when every LDAP server is down', async () => {
      await createDomain(admin, contosoDomain({ name: 'Down', domain_suffix: 'down.test', ldap_urls: ['ldaps://dead.contoso.test:636'] }));
      const r = await login('helpdesk1@down.test', PASSWORDS.helpdesk1);
      assert.equal(r.status, 401);
      assert.equal(r.body.error, GENERIC);
    });

    it('survives LDAP-filter-injection attempts in the username', async () => {
      for (const u of ['*)(objectClass=*@contoso.test', 'helpdesk1)(|(cn=*@contoso.test', 'a\\00b@contoso.test']) {
        const r = await login(u, 'x');
        assert.equal(r.status, 401, u);
      }
      const filters = app.ldapLog().filter((e) => e.op === 'search').map((e) => e.filter).join('\n');
      assert.ok(!filters.includes('(objectClass=*@'), 'raw injection reached the directory filter');
      assert.equal((await app.newUserClient().get('/api/health')).status, 200);
    });
  });

  describe('session lifecycle', () => {
    let c;
    before(async () => { c = await app.userSession('helpdesk1@contoso.test', PASSWORDS.helpdesk1); });

    it('/me describes the session and slides the expiry', async () => {
      const r = await c.get('/api/auth/me');
      assert.equal(r.status, 200);
      assert.equal(r.body.username, 'helpdesk1@contoso.test');
      assert.equal(r.body.domain, 'Contoso');
      assert.equal(r.headers.get('x-session-timeout'), '7200');
      assert.ok(setCookieLine(r, 'user_token'));
    });

    it('/me is 401 without a cookie', async () => {
      assert.equal((await app.newUserClient().get('/api/auth/me')).status, 401);
    });

    it('applies a changed session timeout to new sign-ins', async () => {
      await admin.put('/api/admin/session-config', { userTimeoutMinutes: 30, adminTimeoutMinutes: 480 });
      const r = await login('helpdesk1@contoso.test', PASSWORDS.helpdesk1);
      assert.equal(r.body.sessionTimeoutSeconds, 1800);
      await admin.put('/api/admin/session-config', { userTimeoutMinutes: 120, adminTimeoutMinutes: 480 });
    });

    it('logout clears the cookie and is audited (with the timeout reason when given)', async () => {
      const a = await app.userSession('helpdesk1@contoso.test', PASSWORDS.helpdesk1);
      assert.equal((await a.post('/api/auth/logout', {})).body.ok, true);
      assert.equal((await a.get('/api/auth/me')).status, 401);
      const b = await app.userSession('nested1@contoso.test', PASSWORDS.nested1);
      await b.post('/api/auth/logout', { reason: 'timeout' });
      const [row] = await auditRows(admin, 'eventType=logout');
      assert.equal(row.actor_username, 'nested1@contoso.test');
      assert.equal(row.detail, 'Signed out automatically after session timeout');
    });

    it('logout without a session is harmless', async () => {
      assert.equal((await app.newUserClient().post('/api/auth/logout', {})).status, 200);
    });
  });

  describe('token forgery and role confusion', () => {
    const asCookie = (t) => ({ headers: { cookie: `user_token=${t}` } });
    const base = { username: 'helpdesk1@contoso.test', domainId: 1, bindDn: 'CN=x', pwd: 'AAAA' };

    it('rejects wrong-secret, expired, unsigned and tampered tokens', async () => {
      const c = app.newUserClient();
      const wrong = jwt.sign({ ...base, role: 'user' }, 'other', { expiresIn: 600 });
      const expired = jwt.sign({ ...base, role: 'user' }, TEST_JWT_SECRET, { expiresIn: -60 });
      const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
      const none = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ ...base, role: 'user' })}.`;
      const good = (await app.userSession('helpdesk1@contoso.test', PASSWORDS.helpdesk1)).jar.get('user_token');
      const [h, , s] = good.split('.');
      const tampered = `${h}.${b64({ ...decodeJwt(good), username: 'victim@contoso.test' })}.${s}`;
      for (const t of [wrong, expired, none, tampered]) {
        assert.equal((await c.get('/api/auth/me', asCookie(t))).status, 401);
        assert.equal((await c.get('/api/users/search?q=abc', asCookie(t))).status, 401);
      }
    });

    it('rejects admin and mfa_pending tokens presented as a user session', async () => {
      for (const role of ['admin', 'mfa_pending']) {
        const t = jwt.sign({ ...base, role }, TEST_JWT_SECRET, { expiresIn: 600 });
        assert.equal((await app.newUserClient().get('/api/users/search?q=abc', asCookie(t))).status, 401, role);
      }
    });

    it('answers a validly-signed session whose encrypted password cannot be decrypted with a clear 401', async () => {
      const t = jwt.sign({ ...base, role: 'user' }, TEST_JWT_SECRET, { expiresIn: 600 });
      const r = await app.newUserClient().get('/api/users/search?q=abc', asCookie(t));
      assert.equal(r.status, 401);
      assert.equal(r.body.error, 'Session invalid, please sign in again');
    });

    it('a user token cannot be used on the admin portal', async () => {
      const userCookie = (await app.userSession('helpdesk1@contoso.test', PASSWORDS.helpdesk1)).jar.get('user_token');
      const r = await app.newAdminClient().get('/api/admin/domains', { headers: { cookie: `admin_token=${userCookie}` } });
      assert.equal(r.status, 401);
    });
  });

  describe('audit switches', () => {
    it('global audit switch off => no rows are written; back on => rows resume', async () => {
      const total = async () => (await admin.get('/api/admin/audit')).body.total;
      await admin.put('/api/admin/settings', { auditLoggingEnabled: false });
      const before = await total();
      await login('ghost@nowhere.test', 'x');
      assert.equal(await total(), before);
      await admin.put('/api/admin/settings', { auditLoggingEnabled: true });
      await login('ghost@nowhere.test', 'x');
      assert.equal(await total(), before + 1);
    });

    it('per-domain audit switch off => that domain stops logging but others continue', async () => {
      await admin.put(`/api/admin/domains/${contoso.id}`, { audit_enabled: false });
      const before = (await admin.get('/api/admin/audit')).body.total;
      await login('helpdesk1@contoso.test', 'bad');
      assert.equal((await admin.get('/api/admin/audit')).body.total, before);
      await login('ghost@nowhere.test', 'x');
      assert.equal((await admin.get('/api/admin/audit')).body.total, before + 1);
      await admin.put(`/api/admin/domains/${contoso.id}`, { audit_enabled: true });
    });

    it('successful logins are audited with the client IP', async () => {
      await login('helpdesk1@contoso.test', PASSWORDS.helpdesk1);
      const [row] = await auditRows(admin, 'eventType=login&success=1');
      assert.equal(row.actor_username, 'helpdesk1@contoso.test');
      assert.equal(row.domain_label, 'Contoso');
      assert.ok(row.ip_address, 'ip recorded');
    });
  });

  describe('secret hygiene', () => {
    it('no password (user, lookup, admin) ever appears in the server logs, even at LOG_LEVEL=debug', async () => {
      const out = app.output();
      assert.ok(out.length > 500, 'expected substantial debug output');
      for (const secret of [...Object.values(PASSWORDS), 'Whatever1!', 'Whatever3!', 'bad-password-1', 'not-the-password', ADMIN_PASSWORD]) {
        assert.ok(!out.includes(secret), `secret "${secret}" leaked into logs`);
      }
    });
  });
});
