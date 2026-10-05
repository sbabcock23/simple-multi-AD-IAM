'use strict';
const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('../helpers/app');
const { startFakeSmtp } = require('../helpers/fakeSmtp');
const { contosoDomain, PASSWORDS } = require('../helpers/directory');
const { createDomain } = require('../helpers/util');

const subjectOf = (data) => (data.split('\r\n').find((l) => /^subject:/i.test(l)) || '').replace(/^subject:\s*/i, '');

describe('e-mail alerts (real nodemailer -> in-process SMTP sink)', () => {
  let app; let admin; let smtp; let domain; let hd;
  before(async () => {
    smtp = await startFakeSmtp();
    app = await startApp();
    admin = await app.adminSession();
    domain = await createDomain(admin, contosoDomain());
    await configureGlobal({ enabled: true });
    hd = await app.userSession('helpdesk1@contoso.test', PASSWORDS.helpdesk1);
  });
  after(async () => { await app.stop(); await smtp.stop(); });

  async function configureGlobal(over = {}) {
    const r = await admin.put('/api/admin/alerts', {
      enabled: true, onLoginSuccess: false, onLoginFailure: true, onAccountAction: true,
      recipients: ['secops@example.test', 'helpdesk-leads@example.test'],
      smtp: { host: '127.0.0.1', port: smtp.port, secure: false, tlsRejectUnauthorized: false, from: 'iam@example.test', username: '' },
      ...over,
    });
    assert.equal(r.status, 200, r.text);
  }
  beforeEach(() => { smtp.messages.length = 0; });

  it('"send test e-mail" delivers to every recipient with the configured From address', async () => {
    const r = await admin.post('/api/admin/alerts/test', {});
    assert.equal(r.status, 200, r.text);
    assert.deepEqual(r.body.recipients, ['secops@example.test', 'helpdesk-leads@example.test']);
    const m = await smtp.waitFor((d) => /IAM Self-Service test alert/.test(d));
    assert.deepEqual(m.to.sort(), ['helpdesk-leads@example.test', 'secops@example.test']);
    assert.equal(m.from, 'iam@example.test');
  });

  it('a failed login sends a "Failed login attempt" alert with user, domain, reason and IP', async () => {
    await app.newUserClient().post('/api/auth/login', { username: 'helpdesk1@contoso.test', password: 'Wrong-Password-1' });
    const m = await smtp.waitFor((d) => /Failed login attempt: helpdesk1@contoso\.test/.test(d));
    assert.match(m.data, /Domain: Contoso/);
    assert.match(m.data, /Reason: invalid_credentials_or_unreachable/);
    assert.match(m.data, /Source IP: \S+/);
  });

  it('alerts never contain the password that was typed', async () => {
    await app.newUserClient().post('/api/auth/login', { username: 'helpdesk1@contoso.test', password: 'Typed-Secret-Pw-9!' });
    const m = await smtp.waitFor((d) => /Failed login attempt/.test(d));
    assert.ok(!m.data.includes('Typed-Secret-Pw-9!'));
  });

  it('an unknown domain is also alerted (using the global config)', async () => {
    await app.newUserClient().post('/api/auth/login', { username: 'x@unknown-domain.test', password: 'x' });
    const m = await smtp.waitFor((d) => /Failed login attempt: x@unknown-domain\.test/.test(d));
    assert.match(m.data, /Domain: unrecognized/);
  });

  it('successful logins are NOT alerted by default, and are once switched on', async () => {
    await app.newUserClient().post('/api/auth/login', { username: 'nested1@contoso.test', password: PASSWORDS.nested1 });
    assert.ok(await smtp.expectNone((d) => /Successful login/.test(d)), 'success alert must be opt-in');
    await configureGlobal({ onLoginSuccess: true });
    await app.newUserClient().post('/api/auth/login', { username: 'nested1@contoso.test', password: PASSWORDS.nested1 });
    await smtp.waitFor((d) => /Successful login: nested1@contoso\.test/.test(d));
    await configureGlobal({ onLoginSuccess: false });
  });

  it('unlock and reset-password actions are alerted with actor, target and result', async () => {
    assert.equal((await hd.post('/api/users/locked.user/unlock', {})).status, 200);
    const u = await smtp.waitFor((d) => /Account unlock Success: locked\.user/.test(d));
    assert.match(u.data, /Performed by: helpdesk1@contoso\.test/);
    assert.equal((await hd.post('/api/users/normal.user/reset-password', { newPassword: 'Alert-Test-Pass1!' })).status, 200);
    const r = await smtp.waitFor((d) => /Password reset Success: normal\.user/.test(d));
    assert.ok(!r.data.includes('Alert-Test-Pass1!'), 'new password must never be e-mailed');
  });

  it('a FAILED action is alerted as a failure with the reason', async () => {
    await hd.post('/api/users/ghost.user/unlock', {});
    const m = await smtp.waitFor((d) => /Account unlock Failure: ghost\.user/.test(d));
    assert.match(m.data, /Detail: User not found/);
  });

  it('the global master switch silences everything', async () => {
    await configureGlobal({ enabled: false });
    await app.newUserClient().post('/api/auth/login', { username: 'helpdesk1@contoso.test', password: 'nope' });
    await hd.post('/api/users/ghost.user/unlock', {});
    assert.ok(await smtp.expectNone(() => true, 1000));
    await configureGlobal({ enabled: true });
  });

  it('each trigger can be disabled individually', async () => {
    await configureGlobal({ onLoginFailure: false });
    await app.newUserClient().post('/api/auth/login', { username: 'helpdesk1@contoso.test', password: 'nope' });
    assert.ok(await smtp.expectNone((d) => /Failed login/.test(d)));
    await hd.post('/api/users/ghost.user/unlock', {});
    await smtp.waitFor((d) => /Account unlock Failure/.test(d));
    await configureGlobal({ onLoginFailure: true });
  });

  it('a domain can switch its own alerts off', async () => {
    await admin.put(`/api/admin/domains/${domain.id}`, { alert_config: { enabled: false } });
    await app.newUserClient().post('/api/auth/login', { username: 'helpdesk1@contoso.test', password: 'nope' });
    assert.ok(await smtp.expectNone((d) => /Failed login attempt: helpdesk1@contoso/.test(d)));
    await admin.put(`/api/admin/domains/${domain.id}`, { alert_config: { enabled: true } });
  });

  it('a domain can override the recipients', async () => {
    await admin.put(`/api/admin/domains/${domain.id}`, { alert_config: { recipients: ['contoso-only@example.test'] } });
    await app.newUserClient().post('/api/auth/login', { username: 'helpdesk1@contoso.test', password: 'nope' });
    const m = await smtp.waitFor((d) => /Failed login attempt: helpdesk1@contoso/.test(d));
    assert.deepEqual(m.to, ['contoso-only@example.test']);
    await admin.put(`/api/admin/domains/${domain.id}`, { alert_config: { recipients: [] } });
  });

  it('a domain can use its own SMTP server (and the global server is then not used)', async () => {
    const other = await startFakeSmtp();
    try {
      await admin.put(`/api/admin/domains/${domain.id}`, {
        alert_config: { smtpOverride: true, smtp: { host: '127.0.0.1', port: other.port, tlsRejectUnauthorized: false, from: 'contoso@example.test' } },
      });
      await app.newUserClient().post('/api/auth/login', { username: 'helpdesk1@contoso.test', password: 'nope' });
      const m = await other.waitFor((d) => /Failed login attempt: helpdesk1@contoso/.test(d));
      assert.equal(m.from, 'contoso@example.test');
      assert.ok(await smtp.expectNone((d) => /Failed login attempt: helpdesk1@contoso/.test(d)));
    } finally {
      await admin.put(`/api/admin/domains/${domain.id}`, { alert_config: { smtpOverride: false } });
      await other.stop();
    }
  });

  it('custom e-mail templates are used for the alert and can be reset', async () => {
    await admin.put('/api/admin/templates/login_failure', { subject: 'ALERT!! {{username}} @ {{domain}}', body: 'custom body for {{username}} from {{ip}}' });
    await app.newUserClient().post('/api/auth/login', { username: 'helpdesk1@contoso.test', password: 'nope' });
    const m = await smtp.waitFor((d) => /ALERT!! helpdesk1@contoso\.test @ Contoso/.test(d));
    assert.match(m.data, /custom body for helpdesk1@contoso\.test from/);
    await admin.del('/api/admin/templates/login_failure');
    smtp.messages.length = 0;
    await app.newUserClient().post('/api/auth/login', { username: 'helpdesk1@contoso.test', password: 'nope' });
    const d = await smtp.waitFor((x) => /Failed login attempt: helpdesk1@contoso/.test(x));
    assert.match(subjectOf(d.data), /^\[IAM Self-Service\] Failed login attempt/);
  });

  it('a template file dropped in the templates directory is picked up without a restart', async () => {
    const fs = require('fs'); const path = require('path');
    fs.writeFileSync(path.join(app.dataDir, 'templates', 'login_failure.subject.txt'), 'FILE-SUBJECT {{username}}\n');
    await app.newUserClient().post('/api/auth/login', { username: 'helpdesk1@contoso.test', password: 'nope' });
    await smtp.waitFor((d) => /FILE-SUBJECT helpdesk1@contoso\.test/.test(d));
    fs.unlinkSync(path.join(app.dataDir, 'templates', 'login_failure.subject.txt'));
  });

  it('an unreachable SMTP server never breaks or slows the user-facing request', async () => {
    await configureGlobal({ smtp: { host: '127.0.0.1', port: 1, secure: false, tlsRejectUnauthorized: false } });
    const started = Date.now();
    const ok = await app.newUserClient().post('/api/auth/login', { username: 'helpdesk1@contoso.test', password: PASSWORDS.helpdesk1 });
    assert.equal(ok.status, 200);
    const bad = await app.newUserClient().post('/api/auth/login', { username: 'helpdesk1@contoso.test', password: 'nope' });
    assert.equal(bad.status, 401);
    assert.ok(Date.now() - started < 4000, 'request waited on SMTP');
    const t = await admin.post('/api/admin/alerts/test', {});
    assert.equal(t.status, 400, 'the explicit test e-mail DOES report the SMTP failure');
    assert.ok(t.body.error);
    await configureGlobal({});
  });
});
