'use strict';
const { describe, it, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { setupUnitEnv } = require('../helpers/env');

const env = setupUnitEnv();
const tpl = require('../../src/templates');

const KEYS = ['login_failure', 'login_success', 'account_action'];

describe('src/templates', () => {
  beforeEach(() => {
    KEYS.forEach((k) => tpl.clearDbOverride(k));
    for (const f of fs.readdirSync(tpl.TEMPLATES_DIR)) fs.unlinkSync(path.join(tpl.TEMPLATES_DIR, f));
  });
  after(() => env.cleanup());

  describe('render', () => {
    it('substitutes {{placeholders}}', () => {
      assert.equal(tpl.render('Hi {{name}} from {{ip}}', { name: 'Ann', ip: '1.2.3.4' }), 'Hi Ann from 1.2.3.4');
    });
    it('leaves unknown placeholders untouched', () => {
      assert.equal(tpl.render('{{known}} {{unknown}}', { known: 'x' }), 'x {{unknown}}');
    });
    it('renders null/undefined values as empty and coerces numbers', () => {
      assert.equal(tpl.render('[{{a}}][{{b}}][{{c}}]', { a: null, b: undefined, c: 5 }), '[][][5]');
    });
    it('does not evaluate or re-expand values (no template injection)', () => {
      assert.equal(tpl.render('{{a}}', { a: '{{b}}', b: 'SECRET' }), '{{b}}');
    });
    it('handles non-string templates', () => {
      assert.equal(tpl.render(undefined, {}), '');
    });
  });

  describe('resolution order: database > file > default', () => {
    it('uses built-in defaults when nothing is customised', () => {
      for (const k of KEYS) {
        const t = tpl.getTemplate(k);
        assert.equal(t.source, 'default');
        assert.equal(t.subject, t.defaultSubject);
        assert.ok(t.placeholders.length > 0);
      }
    });

    it('picks up files from TEMPLATES_DIR (CRLF normalised, trailing newline trimmed)', () => {
      fs.writeFileSync(path.join(tpl.TEMPLATES_DIR, 'login_failure.subject.txt'), 'File subject {{username}}\r\n');
      fs.writeFileSync(path.join(tpl.TEMPLATES_DIR, 'login_failure.body.txt'), 'line1\r\nline2\r\n');
      const t = tpl.getTemplate('login_failure');
      assert.equal(t.source, 'file');
      assert.equal(t.subject, 'File subject {{username}}');
      assert.equal(t.body, 'line1\nline2');
    });

    it('database override beats the file, and clearing it restores the file', () => {
      fs.writeFileSync(path.join(tpl.TEMPLATES_DIR, 'login_failure.subject.txt'), 'from file');
      tpl.setDbOverride('login_failure', { subject: 'from db', body: 'db body' });
      assert.equal(tpl.getTemplate('login_failure').subject, 'from db');
      assert.equal(tpl.getTemplate('login_failure').source, 'database');
      tpl.clearDbOverride('login_failure');
      assert.equal(tpl.getTemplate('login_failure').subject, 'from file');
    });

    it('resolves subject and body independently', () => {
      tpl.setDbOverride('login_success', { subject: 'custom subject', body: '' });
      fs.writeFileSync(path.join(tpl.TEMPLATES_DIR, 'login_success.body.txt'), 'file body');
      const t = tpl.getTemplate('login_success');
      assert.equal(t.subject, 'custom subject');
      assert.equal(t.body, 'file body');
    });

    it('survives a corrupt database override', () => {
      const db = require('../../src/db');
      db.prepare("INSERT INTO settings (key, value) VALUES ('email_template:login_failure', '{bad')").run();
      assert.equal(tpl.getTemplate('login_failure').source, 'default');
    });
  });

  it('renderTemplate fills in the default account_action template', () => {
    const r = tpl.renderTemplate('account_action', {
      action: 'Account unlock', result: 'Success', target: 'bob', actor: 'amy', domain: 'Contoso', detail: '', ip: '1.1.1.1', time: 'now',
    });
    assert.equal(r.subject, '[IAM Self-Service] Account unlock Success: bob');
    assert.match(r.text, /Performed by: amy/);
    assert.ok(!/\{\{/.test(r.text));
  });

  it('rejects unknown template keys', () => {
    assert.throws(() => tpl.getTemplate('nope'), /Unknown email template/);
    assert.throws(() => tpl.setDbOverride('nope', { subject: 'a', body: 'b' }), /Unknown email template/);
  });

  it('lists every built-in template', () => {
    assert.deepEqual(tpl.listTemplates().map((t) => t.key).sort(), [...KEYS].sort());
  });
});
