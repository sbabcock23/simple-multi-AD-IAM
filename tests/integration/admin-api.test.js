'use strict';
const net = require('net');
const path = require('path');
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('../helpers/app');
const { contosoDomain, fabrikamDomain, PASSWORDS } = require('../helpers/directory');
const { createDomain, uniqueSuffix } = require('../helpers/util');

describe('admin API', () => {
  let app; let admin;
  before(async () => { app = await startApp(); admin = await app.adminSession(); });
  after(() => app.stop());

  describe('domains: create', () => {
    it('creates a domain with sensible defaults and a normalised suffix', async () => {
      const d = await createDomain(admin, contosoDomain({ domain_suffix: 'MiXeD.Test', allowed_groups: undefined }));
      assert.equal(d.domain_suffix, 'mixed.test');
      assert.deepEqual(d.allowed_groups, ['Domain Admins']);
      assert.equal(d.enabled, true);
      assert.equal(d.audit_enabled, true);
      assert.equal(d.feature_unlock, true);
      assert.equal(d.feature_reset, true);
      assert.equal(d.feature_force_change, true);
      assert.equal(d.has_lookup_password, false);
      assert.deepEqual(d.ldap_urls, ['ldaps://dc1.contoso.test:636', 'ldaps://dc2.contoso.test:636']);
      assert.ok(Number.isInteger(d.id));
    });

    it('trims and drops blank URL / group entries', async () => {
      const d = await createDomain(admin, contosoDomain({
        domain_suffix: uniqueSuffix(), ldap_urls: ['  ldaps://a.test:636  ', '', '   '], allowed_groups: [' Helpdesk ', ''],
      }));
      assert.deepEqual(d.ldap_urls, ['ldaps://a.test:636']);
      assert.deepEqual(d.allowed_groups, ['Helpdesk']);
    });

    const bad = [
      ['a missing name', { name: '' }, /Missing required fields/],
      ['a missing suffix', { domain_suffix: '' }, /Missing required fields/],
      ['a missing base DN', { base_dn: '' }, /Missing required fields/],
      ['no LDAP servers', { ldap_urls: [] }, /At least one LDAP server is required/],
      ['non-array LDAP servers', { ldap_urls: 'ldaps://a:636' }, /At least one LDAP server is required/],
      ['an http:// "LDAP" URL', { ldap_urls: ['http://example.test'] }, /not a valid ldap:\/\/ or ldaps:\/\/ URL/],
      ['a bare hostname', { ldap_urls: ['dc1.contoso.test'] }, /not a valid ldap/],
      ['a lookup DN without a password', { lookup_bind_dn: 'CN=svc,DC=x', lookup_bind_password: '' }, /password is required/],
    ];
    for (const [label, over, re] of bad) {
      it(`rejects ${label} with 400`, async () => {
        const r = await admin.post('/api/admin/domains', contosoDomain({ domain_suffix: uniqueSuffix(), ...over }));
        assert.equal(r.status, 400);
        assert.match(r.body.error, re);
      });
    }

    it('rejects a duplicate suffix (case-insensitively)', async () => {
      const suffix = uniqueSuffix();
      await createDomain(admin, contosoDomain({ domain_suffix: suffix }));
      const r = await admin.post('/api/admin/domains', contosoDomain({ domain_suffix: suffix.toUpperCase() }));
      assert.equal(r.status, 400);
      assert.match(r.body.error, /already configured/);
    });

    it('stores SQL-metacharacters in names literally (parameterised queries)', async () => {
      const name = "Robert'); DROP TABLE domains;--";
      const d = await createDomain(admin, contosoDomain({ name, domain_suffix: uniqueSuffix() }));
      const list = await admin.get('/api/admin/domains');
      assert.equal(list.status, 200);
      assert.ok(list.body.some((x) => x.id === d.id && x.name === name));
    });
  });

  describe('domains: secrets are write-only', () => {
    it('never returns the lookup password (create, list)', async () => {
      const d = await admin.post('/api/admin/domains', fabrikamDomain({ domain_suffix: uniqueSuffix() }));
      assert.equal(d.status, 200);
      assert.equal(d.body.has_lookup_password, true);
      assert.ok(d.body.lookup_bind_dn.startsWith('CN=svc-lookup'));
      const list = await admin.get('/api/admin/domains');
      for (const text of [d.text, list.text]) {
        assert.ok(!text.includes(PASSWORDS.lookup), 'plaintext lookup password leaked');
        assert.ok(!/lookup_bind_password/.test(text), 'password field name leaked');
      }
    });

    it('never returns SMTP or Duo secrets stored inside a domain', async () => {
      const r = await admin.post('/api/admin/domains', contosoDomain({
        domain_suffix: uniqueSuffix(),
        alert_config: { enabled: true, smtpOverride: true, recipients: ['a@x.test'], smtp: { host: 'smtp.x.test', username: 'u', password: 'SmtpS3cret!' } },
        duo_config: { mode: 'enforced', credentialsOverride: true, clientId: 'DIXXXXXXXXXXXXXXXXXX', clientSecret: 'DuoS3cret!', apiHostname: 'api-abc.duosecurity.com', redirectUrl: 'https://x.test/cb' },
      }));
      assert.equal(r.status, 200);
      assert.equal(r.body.alert_config.smtp.hasPassword, true);
      assert.equal(r.body.duo_config.hasClientSecret, true);
      assert.ok(!/SmtpS3cret|DuoS3cret|passwordEnc|clientSecretEnc/.test(r.text), r.text);
      const list = await admin.get('/api/admin/domains');
      assert.ok(!/SmtpS3cret|DuoS3cret|passwordEnc|clientSecretEnc/.test(list.text));
    });

    it('does not store secrets in plaintext on disk', async () => {
      const fs = require('fs');
      const dbFiles = fs.readdirSync(app.dataDir).filter((f) => f.startsWith('iam.db')).map((f) => fs.readFileSync(path.join(app.dataDir, f)));
      const blob = Buffer.concat(dbFiles).toString('latin1');
      for (const secret of [PASSWORDS.lookup, 'SmtpS3cret!', 'DuoS3cret!']) assert.ok(!blob.includes(secret), `${secret} found in the database file`);
    });
  });

  describe('domains: update / delete', () => {
    let id;
    before(async () => { id = (await createDomain(admin, fabrikamDomain({ domain_suffix: uniqueSuffix() }))).id; });

    it('404s for an unknown id', async () => {
      assert.equal((await admin.put('/api/admin/domains/999999', { name: 'x' })).status, 404);
    });

    it('applies a partial update and leaves everything else alone', async () => {
      const r = await admin.put(`/api/admin/domains/${id}`, { name: 'Renamed', feature_reset: false });
      assert.equal(r.status, 200);
      assert.equal(r.body.name, 'Renamed');
      assert.equal(r.body.feature_reset, false);
      assert.equal(r.body.feature_unlock, true);
      assert.deepEqual(r.body.allowed_groups, ['Support']);
      assert.equal(r.body.has_lookup_password, true);
    });

    it('validates URLs and groups on update', async () => {
      assert.equal((await admin.put(`/api/admin/domains/${id}`, { ldap_urls: ['ftp://x'] })).status, 400);
      assert.equal((await admin.put(`/api/admin/domains/${id}`, { ldap_urls: [] })).status, 400);
      const g = await admin.put(`/api/admin/domains/${id}`, { allowed_groups: [] });
      assert.equal(g.status, 400);
      assert.match(g.body.error, /At least one allowed group/);
    });

    it('refuses to move onto another domain\'s suffix', async () => {
      const other = await createDomain(admin, contosoDomain({ domain_suffix: uniqueSuffix() }));
      const r = await admin.put(`/api/admin/domains/${id}`, { domain_suffix: other.domain_suffix });
      assert.equal(r.status, 400);
      assert.match(r.body.error, /already configured/);
    });

    it('keeps the stored lookup password when the same DN is re-saved without one', async () => {
      const r = await admin.put(`/api/admin/domains/${id}`, { lookup_bind_dn: fabrikamDomain().lookup_bind_dn });
      assert.equal(r.status, 200);
      assert.equal(r.body.has_lookup_password, true);
    });

    it('demands a password when the lookup DN changes, and clears both when the DN is emptied', async () => {
      const r = await admin.put(`/api/admin/domains/${id}`, { lookup_bind_dn: 'CN=other,DC=x' });
      assert.equal(r.status, 400);
      assert.match(r.body.error, /password is required/);
      const cleared = await admin.put(`/api/admin/domains/${id}`, { lookup_bind_dn: '' });
      assert.equal(cleared.status, 200);
      assert.equal(cleared.body.lookup_bind_dn, '');
      assert.equal(cleared.body.has_lookup_password, false);
    });

    it('keeps the SMTP password when alert_config is re-saved without one', async () => {
      await admin.put(`/api/admin/domains/${id}`, { alert_config: { smtpOverride: true, smtp: { host: 'h', password: 'pw-1' } } });
      const r = await admin.put(`/api/admin/domains/${id}`, { alert_config: { enabled: false } });
      assert.equal(r.body.alert_config.enabled, false);
      assert.equal(r.body.alert_config.smtp.host, 'h');
      assert.equal(r.body.alert_config.smtp.hasPassword, true);
    });

    it('deletes a domain', async () => {
      const d = await createDomain(admin, contosoDomain({ domain_suffix: uniqueSuffix() }));
      assert.deepEqual((await admin.del(`/api/admin/domains/${d.id}`)).body, { ok: true });
      const list = await admin.get('/api/admin/domains');
      assert.ok(!list.body.some((x) => x.id === d.id));
    });
  });

  describe('connectivity and lookup-account tests', () => {
    it('test-connection validates input', async () => {
      assert.equal((await admin.post('/api/admin/test-connection', { ldap_urls: [] })).status, 400);
      assert.equal((await admin.post('/api/admin/test-connection', { ldap_urls: ['nope'] })).status, 400);
      assert.equal((await admin.post('/api/admin/test-connection', { domainId: 999999 })).status, 404);
    });

    it('test-connection reports per-server reachability', async () => {
      const srv = net.createServer((s) => s.end());
      await new Promise((r) => srv.listen(0, '127.0.0.1', r));
      const open = srv.address().port;
      const probe = net.createServer();
      await new Promise((r) => probe.listen(0, '127.0.0.1', r));
      const closed = probe.address().port;
      await new Promise((r) => probe.close(r));
      const r = await admin.post('/api/admin/test-connection', { ldap_urls: [`ldap://127.0.0.1:${open}`, `ldap://127.0.0.1:${closed}`] });
      await new Promise((res) => srv.close(res));
      assert.equal(r.status, 200);
      assert.equal(r.body.results[0].ok, true);
      assert.equal(r.body.results[1].ok, false);
    });

    it('test-connection works against a saved domain by id', async () => {
      const d = await createDomain(admin, contosoDomain({ domain_suffix: uniqueSuffix(), ldap_urls: ['ldap://127.0.0.1:1'] }));
      const r = await admin.post('/api/admin/test-connection', { domainId: d.id });
      assert.equal(r.status, 200);
      assert.equal(r.body.results.length, 1);
      assert.equal(r.body.results[0].ok, false);
    });

    it('test-lookup validates input', async () => {
      assert.equal((await admin.post('/api/admin/test-lookup', { domainId: 999999 })).status, 404);
      assert.equal((await admin.post('/api/admin/test-lookup', { ldap_urls: ['ldaps://a:636'] })).status, 400);
      assert.equal((await admin.post('/api/admin/test-lookup', { ldap_urls: ['ldaps://a:636'], base_dn: 'DC=x' })).status, 400);
    });

    it('test-lookup binds with the lookup account and finds an account by e-mail', async () => {
      const d = await createDomain(admin, fabrikamDomain({ domain_suffix: uniqueSuffix() }));
      const found = await admin.post('/api/admin/test-lookup', { domainId: d.id, testEmail: 'amy@fabrikam.com' });
      assert.equal(found.status, 200);
      assert.match(found.body.message, /Found a matching account/);
      const missing = await admin.post('/api/admin/test-lookup', { domainId: d.id, testEmail: 'nobody@fabrikam.com' });
      assert.match(missing.body.message, /no account was found/);
      const bindOnly = await admin.post('/api/admin/test-lookup', { domainId: d.id });
      assert.equal(bindOnly.body.message, 'Bind succeeded.');
    });

    it('test-lookup reports a bad lookup password as a 400 error', async () => {
      const d = await createDomain(admin, fabrikamDomain({ domain_suffix: uniqueSuffix() }));
      const r = await admin.post('/api/admin/test-lookup', { domainId: d.id, lookup_bind_password: 'wrong' });
      assert.equal(r.status, 400);
      assert.equal(r.body.ok, false);
    });
  });

  describe('global settings', () => {
    it('audit logging toggle round-trips (default on)', async () => {
      assert.deepEqual((await admin.get('/api/admin/settings')).body, { auditLoggingEnabled: true });
      await admin.put('/api/admin/settings', { auditLoggingEnabled: false });
      assert.equal((await admin.get('/api/admin/settings')).body.auditLoggingEnabled, false);
      await admin.put('/api/admin/settings', { auditLoggingEnabled: true });
      assert.equal((await admin.get('/api/admin/settings')).body.auditLoggingEnabled, true);
    });

    it('session timeouts: defaults, validation and persistence', async () => {
      const def = await admin.get('/api/admin/session-config');
      assert.deepEqual(def.body, { userTimeoutMinutes: 120, adminTimeoutMinutes: 480, min: 5, max: 1440 });
      for (const bad of [{ userTimeoutMinutes: 4, adminTimeoutMinutes: 60 }, { userTimeoutMinutes: 60, adminTimeoutMinutes: 1441 }, { userTimeoutMinutes: 1.5, adminTimeoutMinutes: 60 }, { userTimeoutMinutes: 'x', adminTimeoutMinutes: 60 }, {}]) {
        const r = await admin.put('/api/admin/session-config', bad);
        assert.equal(r.status, 400, JSON.stringify(bad));
        assert.match(r.body.error, /between 5 and 1440/);
      }
      const ok = await admin.put('/api/admin/session-config', { userTimeoutMinutes: 30, adminTimeoutMinutes: 600 });
      assert.equal(ok.status, 200);
      assert.equal((await admin.get('/api/admin/session-config')).body.userTimeoutMinutes, 30);
      const me = await admin.get('/api/admin/me');
      assert.equal(me.headers.get('x-session-timeout'), String(600 * 60), 'new admin timeout applies immediately');
      await admin.put('/api/admin/session-config', { userTimeoutMinutes: 120, adminTimeoutMinutes: 480 });
    });

    it('audit retention: default, validation and update', async () => {
      assert.deepEqual((await admin.get('/api/admin/audit-retention')).body, { days: 0, max: 3650 });
      for (const bad of [-1, 3651, 2.5, 'abc']) assert.equal((await admin.put('/api/admin/audit-retention', { days: bad })).status, 400, String(bad));
      const ok = await admin.put('/api/admin/audit-retention', { days: 90 });
      assert.deepEqual(ok.body, { days: 90, deleted: 0, max: 3650 });
      assert.equal((await admin.get('/api/admin/audit-retention')).body.days, 90);
      await admin.put('/api/admin/audit-retention', { days: 0 });
    });

    it('theme preference is per-admin, validated and returned on login', async () => {
      assert.deepEqual((await admin.get('/api/admin/preferences')).body, { theme: null });
      assert.equal((await admin.put('/api/admin/preferences', { theme: 'blue' })).status, 400);
      assert.deepEqual((await admin.put('/api/admin/preferences', { theme: 'dark' })).body, { theme: 'dark' });
      assert.equal((await admin.get('/api/admin/me')).body.theme, 'dark');
      const fresh = app.newAdminClient();
      const login = await fresh.post('/api/admin/login', { username: 'admin', password: require('../helpers/app').ADMIN_PASSWORD });
      assert.equal(login.body.theme, 'dark');
      await admin.put('/api/admin/preferences', { theme: 'light' });
    });

    it('keepalive is a no-op that refreshes the session', async () => {
      const r = await admin.post('/api/admin/keepalive', {});
      assert.deepEqual(r.body, { ok: true });
      assert.ok(r.headers.get('x-session-timeout'));
    });
  });

  describe('local admin users', () => {
    it('lists admins without exposing password hashes', async () => {
      const r = await admin.get('/api/admin/admins');
      assert.equal(r.status, 200);
      assert.ok(r.body.length >= 1);
      assert.ok(r.body.every((a) => Object.keys(a).sort().join() === 'created_at,id,username'));
      assert.ok(!/hash|\$2[aby]\$/i.test(r.text));
    });

    it('validates new admin input', async () => {
      assert.equal((await admin.post('/api/admin/admins', { username: 'x' })).status, 400);
      assert.equal((await admin.post('/api/admin/admins', { username: 'x', password: 'short' })).status, 400);
      assert.equal((await admin.post('/api/admin/admins', { password: 'LongEnough1' })).status, 400);
    });

    it('creates, authenticates, re-passwords and deletes an admin; protects the last one', async () => {
      const created = await admin.post('/api/admin/admins', { username: 'ops2', password: 'First-Pass-1' });
      assert.equal(created.status, 200);
      const dup = await admin.post('/api/admin/admins', { username: 'ops2', password: 'First-Pass-1' });
      assert.equal(dup.status, 400);
      assert.match(dup.body.error, /already exists/);

      assert.equal((await app.newAdminClient().post('/api/admin/login', { username: 'ops2', password: 'First-Pass-1' })).status, 200);

      assert.equal((await admin.put(`/api/admin/admins/${created.body.id}/password`, { password: 'short' })).status, 400);
      assert.equal((await admin.put(`/api/admin/admins/${created.body.id}/password`, { password: 'Second-Pass-2' })).status, 200);
      assert.equal((await app.newAdminClient().post('/api/admin/login', { username: 'ops2', password: 'First-Pass-1' })).status, 401, 'old password must stop working');
      assert.equal((await app.newAdminClient().post('/api/admin/login', { username: 'ops2', password: 'Second-Pass-2' })).status, 200);

      assert.equal((await admin.del(`/api/admin/admins/${created.body.id}`)).status, 200);
      const all = await admin.get('/api/admin/admins');
      assert.equal(all.body.length, 1);
      const last = await admin.del(`/api/admin/admins/${all.body[0].id}`);
      assert.equal(last.status, 400);
      assert.match(last.body.error, /last remaining admin/);
    });
  });

  describe('global e-mail alert settings', () => {
    it('defaults: off, with a failure/action trigger set and no password', async () => {
      const r = await admin.get('/api/admin/alerts');
      assert.equal(r.body.enabled, false);
      assert.equal(r.body.onLoginSuccess, false);
      assert.equal(r.body.smtp.hasPassword, false);
    });

    it('stores the SMTP password write-only and keeps it when later saves omit it', async () => {
      const put = await admin.put('/api/admin/alerts', {
        enabled: true, recipients: [' a@x.test ', ''], smtp: { host: 'smtp.x.test', port: 2525, username: 'mailer', password: 'GlobalSmtpS3cret!' },
      });
      assert.equal(put.status, 200);
      assert.deepEqual(put.body.recipients, ['a@x.test']);
      assert.equal(put.body.smtp.hasPassword, true);
      assert.ok(!/GlobalSmtpS3cret|passwordEnc/.test(put.text));
      const again = await admin.put('/api/admin/alerts', { enabled: true, smtp: { host: 'smtp2.x.test' } });
      assert.equal(again.body.smtp.hasPassword, true);
      assert.equal(again.body.smtp.host, 'smtp2.x.test');
      assert.equal(again.body.smtp.username, 'mailer', 'untouched fields persist');
      const get = await admin.get('/api/admin/alerts');
      assert.ok(!/GlobalSmtpS3cret|passwordEnc/.test(get.text));
      await admin.put('/api/admin/alerts', { enabled: false, recipients: [], smtp: { host: '' } });
    });

    it('alerts/test explains what is missing', async () => {
      const noRecipients = await admin.post('/api/admin/alerts/test', {});
      assert.equal(noRecipients.status, 400);
      assert.match(noRecipients.body.error, /No recipient email addresses configured/);
      // Recipients are known (global), but no SMTP host has been entered yet.
      await admin.put('/api/admin/alerts', { enabled: false, recipients: ['a@x.test'], smtp: { host: '' } });
      const noHost = await admin.post('/api/admin/alerts/test', {});
      assert.equal(noHost.status, 400);
      assert.match(noHost.body.error, /No SMTP host configured/);
      assert.equal((await admin.post('/api/admin/alerts/test', { domainId: 999999 })).status, 404);
      await admin.put('/api/admin/alerts', { recipients: [] });
    });
  });

  describe('email templates', () => {
    it('lists the three built-in templates as defaults', async () => {
      const r = await admin.get('/api/admin/templates');
      assert.deepEqual(r.body.map((t) => t.key).sort(), ['account_action', 'login_failure', 'login_success']);
      assert.ok(r.body.every((t) => t.source === 'default' && t.subject && t.body && t.placeholders.length));
    });

    it('reports the on-disk templates directory under DATA_DIR', async () => {
      assert.equal((await admin.get('/api/admin/templates-dir')).body.dir, path.join(app.dataDir, 'templates'));
    });

    it('previews with sample values and leaves unknown placeholders alone', async () => {
      const r = await admin.post('/api/admin/templates/login_failure/preview', { subject: 'S {{username}}', body: 'B {{ip}} {{nope}}' });
      assert.equal(r.status, 200);
      assert.deepEqual(r.body, { subject: 'S jdoe@contoso.com', body: 'B 203.0.113.7 {{nope}}' });
    });

    it('overrides, then resets to the default', async () => {
      assert.equal((await admin.put('/api/admin/templates/login_failure', { subject: 'only subject' })).status, 400);
      const put = await admin.put('/api/admin/templates/login_failure', { subject: 'CUSTOM {{username}}', body: 'custom {{reason}}' });
      assert.equal(put.status, 200);
      assert.equal(put.body.source, 'database');
      assert.equal(put.body.subject, 'CUSTOM {{username}}');
      const del = await admin.del('/api/admin/templates/login_failure');
      assert.equal(del.body.source, 'default');
    });

    it('404s for unknown template keys on every verb', async () => {
      assert.equal((await admin.post('/api/admin/templates/nope/preview', { subject: 'a', body: 'b' })).status, 404);
      assert.equal((await admin.put('/api/admin/templates/nope', { subject: 'a', body: 'b' })).status, 404);
      assert.equal((await admin.del('/api/admin/templates/nope')).status, 404);
    });
  });

  describe('Duo (global) settings validation', () => {
    it('rejects an invalid mode and enforcing without full credentials', async () => {
      assert.equal((await admin.put('/api/admin/duo', { mode: 'inherit' })).status, 400);
      const r = await admin.put('/api/admin/duo', { mode: 'enforced' });
      assert.equal(r.status, 400);
      assert.match(r.body.error, /required to enforce MFA/);
    });

    it('defaults to disabled with no secret', async () => {
      const r = await admin.get('/api/admin/duo');
      assert.equal(r.body.mode, 'disabled');
      assert.equal(r.body.hasClientSecret, false);
    });
  });

  describe('audit log + reports on an empty database', () => {
    it('audit list has the paging envelope and clamps page-size/page', async () => {
      const r = await admin.get('/api/admin/audit');
      assert.deepEqual(r.body, { rows: [], total: 0, page: 1, pageSize: 25, totalPages: 1 });
      assert.equal((await admin.get('/api/admin/audit?pageSize=7')).body.pageSize, 25);
      assert.equal((await admin.get('/api/admin/audit?pageSize=100')).body.pageSize, 100);
      assert.equal((await admin.get('/api/admin/audit?page=99')).body.page, 1);
      assert.equal((await admin.get('/api/admin/audit?page=-4')).body.page, 1);
    });

    it('treats filter values as data, not SQL', async () => {
      const r = await admin.get('/api/admin/audit?domainId=1%20OR%201%3D1&eventType=%27%20OR%20%271%27%3D%271');
      assert.equal(r.status, 200);
      assert.equal(r.body.total, 0);
    });

    it('exports a CSV with the documented header', async () => {
      const r = await admin.get('/api/admin/audit/export');
      assert.equal(r.status, 200);
      assert.match(r.headers.get('content-type'), /text\/csv/);
      assert.match(r.headers.get('content-disposition'), /attachment; filename="audit-all-domains-\d{4}-\d{2}-\d{2}\.csv"/);
      assert.equal(r.text.split('\n')[0], 'Timestamp,Domain,Event,Actor,Target,Result,IP Address,Detail');
    });

    it('summary returns zeroed counters and caps the window at 180 days', async () => {
      const r = await admin.get('/api/admin/reports/summary?days=999');
      assert.deepEqual(r.body, { days: 180, logins_success: 0, logins_failed: 0, unlocks: 0, resets: 0, active_users: 0, distinct_ips: 0 });
      assert.equal((await admin.get('/api/admin/reports/summary')).body.days, 30);
    });

    it('every report answers 200 with an array, exports as CSV, and unknown reports 404', async () => {
      for (const key of ['failed-logins', 'successful-events', 'unsuccessful-actions', 'by-user', 'by-target', 'mfa-activity', 'activity-trend']) {
        const r = await admin.get(`/api/admin/reports/${key}`);
        assert.equal(r.status, 200, key);
        assert.ok(Array.isArray(r.body), key);
        const ex = await admin.get(`/api/admin/reports/${key}/export`);
        assert.equal(ex.status, 200, key);
        assert.match(ex.headers.get('content-type'), /text\/csv/);
        assert.match(ex.text, /No data for the selected filters/);
      }
      assert.equal((await admin.get('/api/admin/reports/nope')).status, 404);
      assert.equal((await admin.get('/api/admin/reports/nope/export')).status, 404);
    });
  });
});
