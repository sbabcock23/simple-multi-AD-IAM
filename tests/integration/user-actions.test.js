'use strict';
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('../helpers/app');
const { contosoDomain, PASSWORDS } = require('../helpers/directory');
const { createDomain, auditRows } = require('../helpers/util');

const HELPDESK_DN = 'CN=Help Desk One,OU=Users,DC=contoso,DC=test';
const decodePwd = (entry) => Buffer.from(entry.values[0].base64, 'base64').toString('utf16le');

describe('user portal: directory actions (search, unlock, reset)', () => {
  let app; let admin; let contoso; let hd;
  before(async () => {
    app = await startApp();
    admin = await app.adminSession();
    contoso = await createDomain(admin, contosoDomain());
    hd = await app.userSession('helpdesk1@contoso.test', PASSWORDS.helpdesk1);
  });
  after(() => app.stop());

  const modsSince = (n) => app.ldapLog().slice(n).filter((e) => e.op === 'modify');

  describe('authentication is required', () => {
    const calls = [['GET', '/api/users/search?q=abc'], ['GET', '/api/users/audit'], ['GET', '/api/users/preferences'], ['PUT', '/api/users/preferences'],
      ['GET', '/api/users/normal.user'], ['POST', '/api/users/keepalive'], ['POST', '/api/users/normal.user/unlock'], ['POST', '/api/users/normal.user/reset-password']];
    for (const [m, p] of calls) {
      it(`${m} ${p} -> 401 without a session`, async () => {
        assert.equal((await app.newUserClient().request(m, p, { json: {} })).status, 401);
      });
    }
  });

  describe('search', () => {
    it('returns [] for queries shorter than 2 characters (and does not hit the directory)', async () => {
      const before = app.ldapLog().length;
      assert.deepEqual((await hd.get('/api/users/search?q=a')).body, []);
      assert.deepEqual((await hd.get('/api/users/search')).body, []);
      assert.equal(app.ldapLog().slice(before).filter((e) => e.op === 'search').length, 0);
    });

    it('finds users by partial name and maps the documented fields only', async () => {
      const r = await hd.get('/api/users/search?q=user');
      assert.equal(r.status, 200);
      assert.deepEqual(r.body.map((u) => u.sAMAccountName).sort(), ['disabled.user', 'legacy1', 'locked.user', 'normal.user']); // legacy1's display name is "Legacy User"
      const locked = r.body.find((u) => u.sAMAccountName === 'locked.user');
      assert.deepEqual(Object.keys(locked).sort(), ['cn', 'disabled', 'displayName', 'dn', 'locked', 'mail', 'sAMAccountName', 'userPrincipalName']);
      assert.equal(locked.locked, true);
      assert.equal(r.body.find((u) => u.sAMAccountName === 'disabled.user').disabled, true);
      assert.ok(!/password|pwd/i.test(r.text));
    });

    it('runs as the signed-in user and audits the search', async () => {
      const before = app.ldapLog().length;
      await hd.get('/api/users/search?q=normal');
      const search = app.ldapLog().slice(before).find((e) => e.op === 'search');
      assert.equal(search.by, HELPDESK_DN);
      const [row] = await auditRows(admin, 'eventType=search');
      assert.equal(row.actor_username, 'helpdesk1@contoso.test');
      assert.equal(row.target_identifier, 'normal');
      assert.equal(row.success, 1);
    });

    it('treats LDAP metacharacters literally', async () => {
      const r = await hd.get(`/api/users/search?q=${encodeURIComponent('*)(objectClass=*')}`);
      assert.equal(r.status, 200);
      assert.deepEqual(r.body, []);
    });
  });

  describe('single user lookup', () => {
    it('finds by sAMAccountName and returns 404 for unknown users', async () => {
      const ok = await hd.get('/api/users/normal.user');
      assert.equal(ok.status, 200);
      assert.equal(ok.body.sAMAccountName, 'normal.user');
      assert.equal((await hd.get('/api/users/nobody')).status, 404);
    });

    it('is not shadowed by fixed routes: /audit and /preferences are not user lookups', async () => {
      const a = await hd.get('/api/users/audit');
      assert.ok(Array.isArray(a.body.rows) && 'totalPages' in a.body);
      assert.ok('theme' in (await hd.get('/api/users/preferences')).body);
    });
  });

  describe('unlock', () => {
    it('unlocks a locked account as the signed-in user and records it', async () => {
      assert.equal((await hd.get('/api/users/locked.user')).body.locked, true);
      const before = app.ldapLog().length;
      const r = await hd.post('/api/users/locked.user/unlock', {});
      assert.deepEqual(r.body, { ok: true });
      const [mod] = modsSince(before);
      assert.equal(mod.by, HELPDESK_DN);
      assert.equal(mod.attr, 'lockoutTime');
      assert.deepEqual(mod.values, ['0']);
      assert.equal((await hd.get('/api/users/locked.user')).body.locked, false);
      const [row] = await auditRows(admin, 'eventType=unlock');
      assert.equal(row.target_identifier, 'locked.user');
      assert.equal(row.success, 1);
    });

    it('404s and audits a failure for an unknown target', async () => {
      const before = app.ldapLog().length;
      const r = await hd.post('/api/users/nobody/unlock', {});
      assert.equal(r.status, 404);
      assert.equal(r.body.error, 'User not found');
      assert.equal(modsSince(before).length, 0);
      const [row] = await auditRows(admin, 'eventType=unlock&success=0');
      assert.equal(row.target_identifier, 'nobody');
      assert.equal(row.detail, 'User not found');
    });

    it('surfaces the directory\'s refusal when the user lacks delegated rights (500 + requestId)', async () => {
      const ro = await app.userSession('readonly1@contoso.test', PASSWORDS.readonly1);
      const r = await ro.post('/api/users/normal.user/unlock', {});
      assert.equal(r.status, 500);
      assert.match(r.body.error, /INSUFF_ACCESS_RIGHTS/);
      assert.match(r.body.requestId, /^[0-9a-f]{12}$/);
      const failures = await auditRows(admin, 'eventType=unlock&success=0');
      assert.ok(failures.some((f) => f.actor_username === 'readonly1@contoso.test' && /INSUFF_ACCESS_RIGHTS/.test(f.detail)));
    });
  });

  describe('reset password', () => {
    const reset = (target, body) => hd.post(`/api/users/${target}/reset-password`, body);

    it('requires a password of at least 8 characters', async () => {
      for (const body of [{}, { newPassword: '' }, { newPassword: '1234567' }]) {
        const r = await reset('normal.user', body);
        assert.equal(r.status, 400, JSON.stringify(body));
        assert.equal(r.body.error, 'Password must be at least 8 characters');
      }
    });

    it('sends the new password to AD as quoted UTF-16LE and does NOT force a change by default', async () => {
      const before = app.ldapLog().length;
      const r = await reset('normal.user', { newPassword: 'Brand-N3w-Pass!' });
      assert.deepEqual(r.body, { ok: true });
      const mods = modsSince(before);
      assert.equal(mods.length, 1);
      assert.equal(mods[0].attr, 'unicodePwd');
      assert.equal(mods[0].by, HELPDESK_DN);
      assert.equal(decodePwd(mods[0]), '"Brand-N3w-Pass!"');
      const [row] = await auditRows(admin, 'eventType=reset_password');
      assert.equal(row.target_identifier, 'normal.user');
      assert.equal(row.success, 1);
    });

    it('forceChange additionally sets pwdLastSet=0', async () => {
      const before = app.ldapLog().length;
      await reset('normal.user', { newPassword: 'An0ther-Pass!', forceChange: true });
      assert.deepEqual(modsSince(before).map((m) => m.attr), ['unicodePwd', 'pwdLastSet']);
    });

    it('ignores forceChange when the domain has that feature switched off', async () => {
      await admin.put(`/api/admin/domains/${contoso.id}`, { feature_force_change: false });
      const before = app.ldapLog().length;
      await reset('normal.user', { newPassword: 'Third-Pass-123!', forceChange: true });
      assert.deepEqual(modsSince(before).map((m) => m.attr), ['unicodePwd']);
      await admin.put(`/api/admin/domains/${contoso.id}`, { feature_force_change: true });
    });

    it('404s for an unknown target without touching the directory', async () => {
      const before = app.ldapLog().length;
      assert.equal((await reset('nobody', { newPassword: 'Whatever-123' })).status, 404);
      assert.equal(modsSince(before).length, 0);
    });

    it('refuses over plain ldap:// (password would cross the wire in clear)', async () => {
      await createDomain(admin, contosoDomain({ name: 'Plain', domain_suffix: 'plain.test', ldap_urls: ['ldap://dc1.plain.test:389'] }));
      const plain = await app.userSession('helpdesk1@plain.test', PASSWORDS.helpdesk1);
      const before = app.ldapLog().length;
      const r = await plain.post('/api/users/normal.user/reset-password', { newPassword: 'Whatever-123' });
      assert.equal(r.status, 500);
      assert.match(r.body.error, /LDAPS/);
      assert.equal(modsSince(before).length, 0);
      assert.equal((await plain.post('/api/users/locked.user/unlock', {})).status, 200, 'unlock does not need LDAPS');
    });
  });

  describe('per-domain feature switches', () => {
    it('unlock disabled -> 403 and reflected in /me; re-enable restores it', async () => {
      await admin.put(`/api/admin/domains/${contoso.id}`, { feature_unlock: false });
      const r = await hd.post('/api/users/normal.user/unlock', {});
      assert.equal(r.status, 403);
      assert.equal(r.body.error, 'Account unlock is disabled for this domain');
      assert.equal((await hd.get('/api/auth/me')).body.features.unlock, false);
      await admin.put(`/api/admin/domains/${contoso.id}`, { feature_unlock: true });
      assert.equal((await hd.post('/api/users/normal.user/unlock', {})).status, 200);
    });

    it('reset disabled -> 403', async () => {
      await admin.put(`/api/admin/domains/${contoso.id}`, { feature_reset: false });
      const r = await hd.post('/api/users/normal.user/reset-password', { newPassword: 'Whatever-123' });
      assert.equal(r.status, 403);
      assert.equal(r.body.error, 'Password reset is disabled for this domain');
      await admin.put(`/api/admin/domains/${contoso.id}`, { feature_reset: true });
    });
  });

  describe('domain state changes while a session is open', () => {
    it('disabling the domain locks the session out immediately', async () => {
      const d = await createDomain(admin, contosoDomain({ name: 'Temp', domain_suffix: 'temp.test' }));
      const c = await app.userSession('helpdesk1@temp.test', PASSWORDS.helpdesk1);
      assert.equal((await c.get('/api/auth/me')).status, 200);
      await admin.put(`/api/admin/domains/${d.id}`, { enabled: false });
      const me = await c.get('/api/auth/me');
      assert.equal(me.status, 401);
      assert.equal(me.body.error, 'Domain disabled');
      const search = await c.get('/api/users/search?q=help');
      assert.equal(search.status, 403);
      assert.equal(search.body.error, 'Your domain is currently disabled');
    });

    it('deleting the domain locks the session out too', async () => {
      const d = await createDomain(admin, contosoDomain({ name: 'Gone', domain_suffix: 'gone.test' }));
      const c = await app.userSession('helpdesk1@gone.test', PASSWORDS.helpdesk1);
      await admin.del(`/api/admin/domains/${d.id}`);
      assert.equal((await c.get('/api/auth/me')).status, 401);
      assert.equal((await c.post('/api/users/normal.user/unlock', {})).status, 403);
    });
  });

  describe('personal preferences and activity', () => {
    it('theme is validated, saved per user and returned at sign-in', async () => {
      assert.equal((await hd.put('/api/users/preferences', { theme: 'neon' })).status, 400);
      assert.deepEqual((await hd.put('/api/users/preferences', { theme: 'dark' })).body, { theme: 'dark' });
      assert.deepEqual((await hd.get('/api/users/preferences')).body, { theme: 'dark' });
      const again = await app.newUserClient().post('/api/auth/login', { username: 'helpdesk1@contoso.test', password: PASSWORDS.helpdesk1 });
      assert.equal(again.body.theme, 'dark');
      const other = await app.userSession('nested1@contoso.test', PASSWORDS.nested1);
      assert.deepEqual((await other.get('/api/users/preferences')).body, { theme: null }, 'other users are unaffected');
    });

    it('"my activity" lists only the caller\'s own events, newest first, with paging', async () => {
      const nested = await app.userSession('nested1@contoso.test', PASSWORDS.nested1);
      await nested.get('/api/users/search?q=normal');
      const r = await nested.get('/api/users/audit');
      assert.equal(r.status, 200);
      assert.ok(r.body.rows.length >= 2);
      assert.ok(r.body.rows.every((x) => x.actor_username === 'nested1@contoso.test'));
      const times = r.body.rows.map((x) => x.created_at);
      assert.deepEqual([...times].sort().reverse(), times);
      assert.equal(r.body.pageSize, 25);
      assert.equal((await nested.get('/api/users/audit?pageSize=7')).body.pageSize, 25);
      assert.equal((await nested.get('/api/users/audit?pageSize=100')).body.pageSize, 100);
      assert.equal((await nested.get('/api/users/audit?page=999')).body.page, r.body.totalPages);
    });

    it('keepalive refreshes the session', async () => {
      const r = await hd.post('/api/users/keepalive', {});
      assert.deepEqual(r.body, { ok: true });
      assert.equal(r.headers.get('x-session-timeout'), '7200');
    });
  });

  describe('admin reports reflect the activity above', () => {
    it('summary counts logins, unlocks and resets', async () => {
      const r = await admin.get('/api/admin/reports/summary');
      assert.ok(r.body.logins_success >= 3);
      assert.ok(r.body.unlocks >= 2);
      assert.ok(r.body.resets >= 3);
      assert.ok(r.body.active_users >= 2);
    });

    it('by-target shows who was unlocked / reset how many times', async () => {
      const r = await admin.get('/api/admin/reports/by-target');
      const row = r.body.find((x) => x['Target account'] === 'normal.user');
      assert.ok(row);
      assert.ok(row['Times password reset'] >= 3);
      const locked = r.body.find((x) => x['Target account'] === 'locked.user');
      assert.ok(locked['Times unlocked'] >= 1);
    });

    it('failed-logins aggregates repeated attempts by source and username', async () => {
      const c = app.newUserClient();
      await c.post('/api/auth/login', { username: 'attacker@contoso.test', password: 'a' });
      await c.post('/api/auth/login', { username: 'attacker@contoso.test', password: 'b' });
      const r = await admin.get('/api/admin/reports/failed-logins');
      const row = r.body.find((x) => x['Username entered'] === 'attacker@contoso.test');
      assert.equal(row.Attempts, 2);
      assert.equal(row.Domain, 'Contoso');
    });

    it('exports a filtered audit CSV', async () => {
      const r = await admin.get('/api/admin/audit/export?eventType=unlock&success=1');
      assert.equal(r.status, 200);
      const lines = r.text.split('\n');
      assert.equal(lines[0], 'Timestamp,Domain,Event,Actor,Target,Result,IP Address,Detail');
      assert.ok(lines.length >= 2);
      assert.ok(lines.slice(1).every((l) => l.includes(',unlock,') && l.includes(',Success,')));
      const byDomain = await admin.get(`/api/admin/audit/export?domainId=${contoso.id}`);
      assert.match(byDomain.headers.get('content-disposition'), /audit-contoso\.test-/);
    });

    it('exports a report as CSV with a header row and data', async () => {
      const r = await admin.get('/api/admin/reports/by-user/export');
      assert.equal(r.status, 200);
      assert.match(r.headers.get('content-disposition'), /report-by-user-\d{4}-\d{2}-\d{2}\.csv/);
      assert.match(r.text.split('\n')[0], /^User,Total events,Failed logins/);
      assert.ok(r.text.includes('helpdesk1@contoso.test'));
    });

    it('filters reports by domain and by date range', async () => {
      const inRange = await admin.get(`/api/admin/reports/successful-events?domainId=${contoso.id}`);
      assert.ok(inRange.body.length > 0);
      const future = await admin.get('/api/admin/reports/successful-events?from=2999-01-01T00:00:00.000Z');
      assert.deepEqual(future.body, []);
      const unmatched = await admin.get('/api/admin/reports/failed-logins?domainId=unmatched');
      assert.ok(unmatched.body.every((x) => x.Domain !== 'Contoso'));
    });
  });
});
