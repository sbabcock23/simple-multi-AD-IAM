'use strict';
const { describe, it, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const { setupUnitEnv } = require('../helpers/env');

const env = setupUnitEnv();
const db = require('../../src/db');
const mailer = require('../../src/mailer');

const domainRow = (cfg) => ({ alert_config: cfg });

describe('src/mailer', () => {
  beforeEach(() => db.prepare("UPDATE settings SET value = '{}' WHERE key = 'alert_config'").run());
  after(() => env.cleanup());

  describe('global defaults', () => {
    it('alerts are OFF until an administrator opts in; failures/actions on, successes off', () => {
      const g = mailer.getGlobalConfig();
      assert.equal(g.enabled, false);
      assert.equal(g.onLoginSuccess, false);
      assert.equal(g.onLoginFailure, true);
      assert.equal(g.onAccountAction, true);
      assert.deepEqual(g.recipients, []);
      assert.equal(g.smtp.port, 587);
    });

    it('round-trips global config', () => {
      mailer.setGlobalConfig({ ...mailer.getGlobalConfig(), enabled: true, recipients: ['a@x.test'], smtp: { ...mailer.getGlobalConfig().smtp, host: 'smtp.x.test' } });
      const g = mailer.getGlobalConfig();
      assert.equal(g.enabled, true);
      assert.deepEqual(g.recipients, ['a@x.test']);
      assert.equal(g.smtp.host, 'smtp.x.test');
    });

    it('tolerates a corrupt stored config', () => {
      db.prepare("UPDATE settings SET value = 'oops' WHERE key = 'alert_config'").run();
      assert.equal(mailer.getGlobalConfig().enabled, false);
    });
  });

  describe('resolveEffective (global AND domain switches)', () => {
    const enableGlobal = (over = {}) => mailer.setGlobalConfig({
      ...mailer.getGlobalConfig(), enabled: true, onLoginSuccess: true, recipients: ['global@x.test'],
      smtp: { ...mailer.getGlobalConfig().smtp, host: 'smtp.global.test' }, ...over,
    });

    it('with no domain it is just the global config', () => {
      enableGlobal();
      const e = mailer.resolveEffective(null);
      assert.equal(e.enabled, true);
      assert.deepEqual(e.recipients, ['global@x.test']);
    });

    it('is disabled when the global master switch is off, even if the domain is on', () => {
      assert.equal(mailer.resolveEffective(domainRow({ enabled: true })).enabled, false);
    });

    it('is disabled when the domain is off, even if global is on', () => {
      enableGlobal();
      assert.equal(mailer.resolveEffective(domainRow({ enabled: false })).enabled, false);
    });

    it('each trigger needs BOTH levels', () => {
      enableGlobal({ onLoginSuccess: true, onLoginFailure: false });
      const e = mailer.resolveEffective(domainRow({ onLoginSuccess: false, onLoginFailure: true }));
      assert.equal(e.onLoginSuccess, false); // domain off
      assert.equal(e.onLoginFailure, false); // global off
    });

    it('domain recipients override global ones; empty falls back to global', () => {
      enableGlobal();
      assert.deepEqual(mailer.resolveEffective(domainRow({ recipients: ['dom@x.test'] })).recipients, ['dom@x.test']);
      assert.deepEqual(mailer.resolveEffective(domainRow({ recipients: [] })).recipients, ['global@x.test']);
    });

    it('domain SMTP is used only when smtpOverride is set', () => {
      enableGlobal();
      const smtp = { host: 'smtp.domain.test' };
      assert.equal(mailer.resolveEffective(domainRow({ smtp })).smtp.host, 'smtp.global.test');
      assert.equal(mailer.resolveEffective(domainRow({ smtpOverride: true, smtp })).smtp.host, 'smtp.domain.test');
    });

    it('accepts alert_config as a raw JSON string or a corrupt one', () => {
      enableGlobal();
      assert.equal(mailer.resolveEffective(domainRow(JSON.stringify({ enabled: false }))).enabled, false);
      assert.equal(mailer.resolveEffective(domainRow('{{{')).enabled, true);
    });
  });

  describe('sanitizeSmtp', () => {
    it('never exposes the encrypted password, only a boolean', () => {
      const s = mailer.sanitizeSmtp({ host: 'h', passwordEnc: 'ciphertext' });
      assert.equal(s.hasPassword, true);
      assert.ok(!('passwordEnc' in s));
      assert.equal(mailer.sanitizeSmtp({ host: 'h', passwordEnc: '' }).hasPassword, false);
    });
  });

  describe('email builders', () => {
    it('login failure mentions the user, reason and IP; falls back for unknown values', () => {
      const m = mailer.loginFailureEmail({ username: 'x@y.test', domainName: null, reason: 'bad', ip: '', time: 't' });
      assert.match(m.subject, /Failed login attempt: x@y.test/);
      assert.match(m.text, /Domain: unrecognized/);
      assert.match(m.text, /Source IP: unknown/);
    });

    it('login success', () => {
      const m = mailer.loginSuccessEmail({ username: 'x@y.test', domainName: 'Contoso', ip: '1.1.1.1', time: 't' });
      assert.match(m.subject, /Successful login: x@y.test/);
    });

    it('account action labels unlock vs reset and success vs failure', () => {
      const u = mailer.accountActionEmail({ actor: 'a', target: 'b', domainName: 'D', action: 'unlock', success: true, ip: 'i', time: 't' });
      assert.equal(u.subject, '[IAM Self-Service] Account unlock Success: b');
      const r = mailer.accountActionEmail({ actor: 'a', target: 'b', domainName: 'D', action: 'reset_password', success: false, detail: 'denied', ip: 'i', time: 't' });
      assert.equal(r.subject, '[IAM Self-Service] Password reset Failure: b');
      assert.match(r.text, /Detail: denied/);
    });
  });

  describe('sendAlert', () => {
    it('never throws or rejects when alerts are disabled / unconfigured', async () => {
      assert.doesNotThrow(() => mailer.sendAlert({ domainRow: null, category: 'login_failure', subject: 's', text: 't' }));
      await new Promise((r) => setTimeout(r, 20));
    });
  });

  describe('sendTestEmail', () => {
    it('requires recipients and an SMTP host', async () => {
      await assert.rejects(mailer.sendTestEmail({ domainRow: null }), /No recipient email addresses configured/);
      mailer.setGlobalConfig({ ...mailer.getGlobalConfig(), recipients: ['a@x.test'] });
      await assert.rejects(mailer.sendTestEmail({ domainRow: null }), /No SMTP host configured/);
    });
  });
});
