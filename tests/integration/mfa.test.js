'use strict';
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('../helpers/app');
const { contosoDomain, PASSWORDS } = require('../helpers/directory');
const { createDomain, auditRows, decodeJwt, setCookieLine, uniqueSuffix } = require('../helpers/util');

const DUO = {
  clientId: 'DIABCDEFGHIJKLMNOPQR', clientSecret: 'S'.repeat(40),
  apiHostname: 'api-1234abcd.duosecurity.com', redirectUrl: 'https://iam.example.test/api/auth/duo-callback',
};
const GOOD_CODE = 'good-code'; // understood by the fake Duo SDK (tests/helpers/fakeServices.preload.js)

describe('Cisco Duo MFA (SDK faked, real app flow)', () => {
  let app; let admin;
  before(async () => { app = await startApp({ duo: true }); admin = await app.adminSession(); });
  after(() => app.stop());

  const setGlobalDuo = (cfg) => admin.put('/api/admin/duo', cfg);
  const startLogin = async (username, password) => {
    const c = app.newUserClient();
    const r = await c.post('/api/auth/login', { username, password });
    return { c, r };
  };
  const stateOf = (redirectUrl) => new URL(redirectUrl).searchParams.get('state');

  describe('admin configuration', () => {
    it('stores the client secret write-only', async () => {
      const r = await setGlobalDuo({ mode: 'disabled', ...DUO });
      assert.equal(r.status, 200);
      assert.equal(r.body.hasClientSecret, true);
      assert.ok(!r.text.includes(DUO.clientSecret) && !/clientSecretEnc/.test(r.text));
      const g = await admin.get('/api/admin/duo');
      assert.ok(!g.text.includes(DUO.clientSecret) && !/clientSecretEnc/.test(g.text));
      assert.equal(g.body.clientId, DUO.clientId);
    });

    it('keeps the saved secret when later saves omit it', async () => {
      await setGlobalDuo({ mode: 'disabled', redirectUrl: DUO.redirectUrl });
      assert.equal((await admin.get('/api/admin/duo')).body.hasClientSecret, true);
    });

    it('"Test" accepts valid credentials, using the saved secret when none is typed', async () => {
      const typed = await admin.post('/api/admin/duo/test', DUO);
      assert.equal(typed.status, 200);
      assert.equal(typed.body.ok, true);
      const saved = await admin.post('/api/admin/duo/test', {});
      assert.equal(saved.status, 200);
    });

    it('"Test" reports a bad API hostname and a bad secret as 400s', async () => {
      const host = await admin.post('/api/admin/duo/test', { ...DUO, apiHostname: 'admin-1234abcd.duosecurity.com' });
      assert.equal(host.status, 400);
      assert.match(host.body.error, /doesn't look like a Duo API hostname/);
      const secret = await admin.post('/api/admin/duo/test', { ...DUO, clientSecret: 'bad-secret' });
      assert.equal(secret.status, 400);
      assert.match(secret.body.error, /Invalid client secret/);
    });

    it('"Test" requires every field', async () => {
      await admin.put('/api/admin/duo', { mode: 'disabled', clientId: '', apiHostname: '', redirectUrl: '' });
      const r = await admin.post('/api/admin/duo/test', { scope: 'global', clientId: 'x' });
      assert.equal(r.status, 400);
      assert.match(r.body.error, /all required to test/);
      await setGlobalDuo({ mode: 'disabled', ...DUO });
    });

    it('a domain form without its own override tests the saved GLOBAL application', async () => {
      const r = await admin.post('/api/admin/duo/test', { scope: 'domain', credentialsOverride: false });
      assert.equal(r.status, 200);
    });
  });

  describe('enforced globally', () => {
    let domain;
    before(async () => {
      domain = await createDomain(admin, contosoDomain());
      assert.equal((await setGlobalDuo({ mode: 'enforced', ...DUO })).status, 200);
    });
    after(async () => { await setGlobalDuo({ mode: 'disabled' }); });

    it('password alone does NOT create a session: returns a Duo redirect and a pending cookie', async () => {
      const { c, r } = await startLogin('helpdesk1@contoso.test', PASSWORDS.helpdesk1);
      assert.equal(r.status, 200);
      assert.equal(r.body.mfaRequired, true);
      assert.ok(r.body.redirectUrl.startsWith(`https://${DUO.apiHostname}/`));
      assert.ok(stateOf(r.body.redirectUrl));
      assert.equal(c.jar.has('user_token'), false, 'no session before MFA');
      assert.equal(c.jar.has('mfa_pending'), true);
      assert.equal((await c.get('/api/auth/me')).status, 401);
      assert.equal((await c.get('/api/users/search?q=help')).status, 401);
    });

    it('the pending cookie is httpOnly + SameSite=Lax and is not a usable session token', async () => {
      const { c, r } = await startLogin('helpdesk1@contoso.test', PASSWORDS.helpdesk1);
      const line = setCookieLine(r, 'mfa_pending');
      assert.match(line, /HttpOnly/i);
      assert.match(line, /SameSite=Lax/i);
      const payload = decodeJwt(c.jar.get('mfa_pending'));
      assert.equal(payload.role, 'mfa_pending');
      assert.equal(payload.exp - payload.iat, 300);
      assert.ok(!c.jar.get('mfa_pending').includes(PASSWORDS.helpdesk1));
      const asUser = await app.newUserClient().get('/api/users/search?q=help', { headers: { cookie: `user_token=${c.jar.get('mfa_pending')}` } });
      assert.equal(asUser.status, 401);
    });

    it('wrong password never reaches the Duo step', async () => {
      const { c, r } = await startLogin('helpdesk1@contoso.test', 'wrong');
      assert.equal(r.status, 401);
      assert.equal(c.jar.has('mfa_pending'), false);
    });

    it('completing Duo with a good code yields a full session and redirects home', async () => {
      const { c, r } = await startLogin('helpdesk1@contoso.test', PASSWORDS.helpdesk1);
      const cb = await c.get(`/api/auth/duo-callback?state=${stateOf(r.body.redirectUrl)}&duo_code=${GOOD_CODE}`);
      assert.equal(cb.status, 302);
      assert.equal(cb.headers.get('location'), '/');
      assert.equal(c.jar.has('user_token'), true);
      assert.equal(c.jar.has('mfa_pending'), false, 'pending cookie is cleared');
      const me = await c.get('/api/auth/me');
      assert.equal(me.status, 200);
      assert.equal(me.body.username, 'helpdesk1@contoso.test');
      // the cached AD password survived the round trip and works for directory calls
      const search = await c.get('/api/users/search?q=normal');
      assert.equal(search.status, 200);
      assert.equal(search.body[0].sAMAccountName, 'normal.user');
    });

    it('audits the challenge and the completed login', async () => {
      const { c, r } = await startLogin('nested1@contoso.test', PASSWORDS.nested1);
      await c.get(`/api/auth/duo-callback?state=${stateOf(r.body.redirectUrl)}&duo_code=${GOOD_CODE}`);
      const rows = (await auditRows(admin)).filter((x) => x.actor_username === 'nested1@contoso.test');
      assert.ok(rows.some((x) => x.event_type === 'mfa_challenge' && x.success === 1));
      assert.ok(rows.some((x) => x.event_type === 'login' && x.success === 1));
    });

    const failures = [
      ['a wrong state value (CSRF)', (s) => `state=tampered&duo_code=${GOOD_CODE}`],
      ['a missing state', () => `duo_code=${GOOD_CODE}`],
      ['a missing duo_code', (s) => `state=${s}`],
      ['a Duo-reported error (e.g. user cancelled)', (s) => `state=${s}&error=access_denied&duo_code=${GOOD_CODE}`],
      ['a duo_code Duo rejects', (s) => `state=${s}&duo_code=forged`],
    ];
    for (const [label, query] of failures) {
      it(`${label} -> /?error=mfa_failed and NO session`, async () => {
        const { c, r } = await startLogin('helpdesk1@contoso.test', PASSWORDS.helpdesk1);
        const cb = await c.get(`/api/auth/duo-callback?${query(stateOf(r.body.redirectUrl))}`);
        assert.equal(cb.status, 302);
        assert.equal(cb.headers.get('location'), '/?error=mfa_failed');
        assert.equal(c.jar.has('user_token'), false);
        assert.equal((await c.get('/api/auth/me')).status, 401);
      });
    }

    it('failed MFA is audited as a login failure and shows in the MFA report', async () => {
      const { c, r } = await startLogin('helpdesk1@contoso.test', PASSWORDS.helpdesk1);
      await c.get(`/api/auth/duo-callback?state=${stateOf(r.body.redirectUrl)}&duo_code=forged`);
      const [row] = await auditRows(admin, 'eventType=login&success=0');
      assert.equal(row.detail, 'MFA verification failed');
      const rep = await admin.get('/api/admin/reports/mfa-activity');
      const mine = rep.body.find((x) => x.User === 'helpdesk1@contoso.test');
      assert.ok(mine['Challenges sent'] >= 1);
      assert.ok(mine['MFA failures'] >= 1);
      assert.ok(mine['Completed logins'] >= 1);
    });

    it('a callback without the pending cookie -> /?error=mfa_session_expired', async () => {
      const { r } = await startLogin('helpdesk1@contoso.test', PASSWORDS.helpdesk1);
      const stranger = app.newUserClient();
      const cb = await stranger.get(`/api/auth/duo-callback?state=${stateOf(r.body.redirectUrl)}&duo_code=${GOOD_CODE}`);
      assert.equal(cb.headers.get('location'), '/?error=mfa_session_expired');
      assert.equal(stranger.jar.has('user_token'), false);
    });

    it('the callback cannot be replayed once the pending cookie has been consumed', async () => {
      const { c, r } = await startLogin('helpdesk1@contoso.test', PASSWORDS.helpdesk1);
      const url = `/api/auth/duo-callback?state=${stateOf(r.body.redirectUrl)}&duo_code=${GOOD_CODE}`;
      const stolenCookie = c.jar.get('mfa_pending');
      assert.equal((await c.get(url)).headers.get('location'), '/');
      assert.equal((await app.newUserClient().get(url)).headers.get('location'), '/?error=mfa_session_expired');
      // Documented limitation: the pending token is a stateless JWT, so a copy of the cookie
      // is still accepted until its 5-minute expiry (see security.test.js "known gaps").
      assert.ok(stolenCookie);
    });

    it('a state issued to a different login attempt is rejected', async () => {
      const a = await startLogin('helpdesk1@contoso.test', PASSWORDS.helpdesk1);
      const b = await startLogin('helpdesk1@contoso.test', PASSWORDS.helpdesk1);
      const cb = await a.c.get(`/api/auth/duo-callback?state=${stateOf(b.r.body.redirectUrl)}&duo_code=${GOOD_CODE}`);
      assert.equal(cb.headers.get('location'), '/?error=mfa_failed');
    });

    it('the callback endpoint never answers with JSON or a stack trace for junk input', async () => {
      const c = app.newUserClient();
      const r = await c.get('/api/auth/duo-callback?state[]=a&duo_code[]=b');
      assert.equal(r.status, 302);
      assert.match(r.headers.get('location'), /^\/\?error=/);
    });
  });

  describe('per-domain overrides', () => {
    afterEachGlobal();
    function afterEachGlobal() { after(async () => { await setGlobalDuo({ mode: 'disabled' }); }); }

    it('a domain set to "disabled" skips MFA even when global is enforced', async () => {
      await setGlobalDuo({ mode: 'enforced', ...DUO });
      await createDomain(admin, contosoDomain({ name: 'NoMfa', domain_suffix: 'nomfa.test', duo_config: { mode: 'disabled' } }));
      const { c, r } = await startLogin('helpdesk1@nomfa.test', PASSWORDS.helpdesk1);
      assert.equal(r.status, 200);
      assert.equal(r.body.mfaRequired, undefined);
      assert.equal(c.jar.has('user_token'), true);
    });

    it('a domain set to "enforced" requires MFA even when global is disabled', async () => {
      await setGlobalDuo({ mode: 'disabled', ...DUO });
      await createDomain(admin, contosoDomain({ name: 'Strict', domain_suffix: 'strict.test', duo_config: { mode: 'enforced' } }));
      const { c, r } = await startLogin('helpdesk1@strict.test', PASSWORDS.helpdesk1);
      assert.equal(r.body.mfaRequired, true);
      assert.equal(c.jar.has('user_token'), false);
    });

    it('a domain can use its own Duo application (client id and host in the redirect)', async () => {
      await createDomain(admin, contosoDomain({
        name: 'OwnDuo', domain_suffix: 'ownduo.test',
        duo_config: { mode: 'enforced', credentialsOverride: true, clientId: 'DIDOMAINAPPLICATION00', clientSecret: 'D'.repeat(40), apiHostname: 'https://api-99999999.duosecurity.com/', redirectUrl: 'https://iam.example.test/api/auth/duo-callback' },
      }));
      const { r } = await startLogin('helpdesk1@ownduo.test', PASSWORDS.helpdesk1);
      assert.equal(r.body.mfaRequired, true);
      const u = new URL(r.body.redirectUrl);
      assert.equal(u.hostname, 'api-99999999.duosecurity.com', 'scheme/path pasted by the admin are normalised');
      assert.equal(u.searchParams.get('client_id'), 'DIDOMAINAPPLICATION00');
    });

    it('FAILS CLOSED: MFA enforced but not configured -> 503, no session, audited', async () => {
      await setGlobalDuo({ mode: 'disabled', clientId: '', apiHostname: '', redirectUrl: '' });
      // global secret may remain, but id/host/redirect are blank so the app is unconfigured
      const d = await createDomain(admin, contosoDomain({ name: 'Broken', domain_suffix: 'broken.test', duo_config: { mode: 'enforced' } }));
      const { c, r } = await startLogin('helpdesk1@broken.test', PASSWORDS.helpdesk1);
      assert.equal(r.status, 503);
      assert.match(r.body.error, /required but not configured correctly/);
      assert.equal(c.jar.has('user_token'), false);
      assert.equal(c.jar.has('mfa_pending'), false);
      const [row] = await auditRows(admin, 'eventType=login&success=0');
      assert.equal(row.detail, 'MFA is enforced but not fully configured');
      assert.equal(row.domain_id, d.id);
    });
  });

  describe('Duo secrets and logs', () => {
    it('no Duo secret ever appears in the server logs', () => {
      const out = app.output();
      assert.ok(!out.includes(DUO.clientSecret));
      assert.ok(!out.includes('D'.repeat(40)));
    });
  });
});
