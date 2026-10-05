'use strict';
const { describe, it, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const { setupUnitEnv } = require('../helpers/env');

const env = setupUnitEnv();
const db = require('../../src/db');
const audit = require('../../src/audit');

const req = (over = {}) => ({ headers: {}, socket: { remoteAddress: '10.0.0.5' }, ip: '10.0.0.5', ...over });
const rows = () => db.prepare('SELECT * FROM audit_log ORDER BY id').all();
const event = (over = {}) => ({ eventType: 'login', actorUsername: 'u@x.test', success: true, ...over });

function addDomain(auditEnabled = 1) {
  const now = new Date().toISOString();
  return db.prepare(`INSERT INTO domains (name, domain_suffix, ldap_urls, base_dn, audit_enabled, created_at, updated_at)
    VALUES ('D', 'd' || abs(random()) || '.test', '[]', 'DC=d', ?, ?, ?)`).run(auditEnabled, now, now).lastInsertRowid;
}

describe('src/audit', () => {
  beforeEach(() => {
    db.prepare('DELETE FROM audit_log').run();
    db.prepare("UPDATE settings SET value = '1' WHERE key = 'audit_logging_enabled'").run();
  });
  after(() => env.cleanup());

  it('records an event with all fields', () => {
    audit.logEvent(req(), event({ domainId: null, domainLabel: 'x.test', targetIdentifier: 'bob', detail: 'why', success: false }));
    const [r] = rows();
    assert.equal(r.event_type, 'login');
    assert.equal(r.actor_username, 'u@x.test');
    assert.equal(r.target_identifier, 'bob');
    assert.equal(r.success, 0);
    assert.equal(r.detail, 'why');
    assert.equal(r.domain_label, 'x.test');
    assert.equal(r.ip_address, '10.0.0.5');
    assert.ok(!Number.isNaN(Date.parse(r.created_at)));
  });

  it('is skipped when the GLOBAL audit switch is off', () => {
    db.prepare("UPDATE settings SET value = '0' WHERE key = 'audit_logging_enabled'").run();
    assert.equal(audit.isGlobalAuditEnabled(), false);
    audit.logEvent(req(), event());
    assert.equal(rows().length, 0);
  });

  it('is skipped when the DOMAIN audit switch is off, but not for other domains', () => {
    const off = addDomain(0); const on = addDomain(1);
    audit.logEvent(req(), event({ domainId: off }));
    audit.logEvent(req(), event({ domainId: on }));
    assert.deepEqual(rows().map((r) => r.domain_id), [on]);
  });

  it('events with no matching domain are governed only by the global switch', () => {
    assert.equal(audit.isDomainAuditEnabled(null), true);
    audit.logEvent(req(), event({ domainId: null }));
    assert.equal(rows().length, 1);
  });

  it('never throws even if the insert fails (auditing must not break requests)', () => {
    assert.doesNotThrow(() => audit.logEvent(req(), { eventType: 'login', actorUsername: null, success: true }));
  });

  describe('getClientIp', () => {
    it('uses the socket address by default', () => {
      assert.equal(audit.getClientIp(req()), '10.0.0.5');
    });
    it('honours the first X-Forwarded-For hop (current behaviour)', () => {
      assert.equal(audit.getClientIp(req({ headers: { 'x-forwarded-for': '203.0.113.9, 10.0.0.1' } })), '203.0.113.9');
    });
    it('returns an empty string when nothing is known', () => {
      assert.equal(audit.getClientIp({ headers: {} }), '');
    });
  });
});
