'use strict';
const { describe, it, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const { setupUnitEnv } = require('../helpers/env');

const env = setupUnitEnv();
const db = require('../../src/db');
const retention = require('../../src/auditRetention');

const daysAgo = (n) => new Date(Date.now() - n * 86400000).toISOString();
function addRow(createdAt, actor = 'u@x.test') {
  db.prepare(`INSERT INTO audit_log (created_at, event_type, actor_username, success) VALUES (?, 'login', ?, 1)`).run(createdAt, actor);
}
const count = () => db.prepare('SELECT COUNT(*) n FROM audit_log').get().n;

describe('src/auditRetention', () => {
  beforeEach(() => {
    db.prepare('DELETE FROM audit_log').run();
    db.prepare("DELETE FROM settings WHERE key = 'audit_retention_days'").run();
  });
  after(() => env.cleanup());

  it('defaults to 0 (keep forever) so upgrades never delete anything', () => {
    assert.equal(retention.getDays(), 0);
    addRow(daysAgo(5000));
    assert.deepEqual(retention.purge(), { days: 0, deleted: 0 });
    assert.equal(count(), 1);
  });

  it('purges only records older than the retention window', () => {
    addRow(daysAgo(100)); addRow(daysAgo(31)); addRow(daysAgo(29)); addRow(daysAgo(1));
    retention.setDays(30);
    assert.deepEqual(retention.purge(), { days: 30, deleted: 2 });
    assert.equal(count(), 2);
    // it must be the OLD rows that went, and the recent ones that stayed
    const ages = db.prepare('SELECT created_at FROM audit_log').all()
      .map((r) => (Date.now() - Date.parse(r.created_at)) / 86400000);
    assert.ok(ages.every((a) => a < 30), `an old record survived the purge: ${ages}`);
  });

  it('is idempotent', () => {
    addRow(daysAgo(100));
    retention.setDays(30);
    retention.purge();
    assert.equal(retention.purge().deleted, 0);
  });

  it('setting 0 again switches purging off', () => {
    retention.setDays(30);
    retention.setDays(0);
    addRow(daysAgo(1000));
    assert.equal(retention.purge().deleted, 0);
  });

  for (const bad of [-1, 3651, 1.5, 'abc', undefined, NaN]) {
    it(`rejects ${String(bad)}`, () => {
      assert.throws(() => retention.setDays(bad), (e) => e.status === 400);
      assert.equal(retention.getDays(), 0);
    });
  }

  // KNOWN ISSUE (reported, not failing the build): Number(null) / Number('') / Number(false) are all 0,
  // so a missing/blank value from the client silently switches retention OFF ("keep forever")
  // instead of being rejected as invalid input. Remove `todo` once setDays() validates the type.
  it('rejects null / empty-string / boolean instead of coercing them to 0', { todo: 'Number(null) === 0 is accepted as "keep forever"' }, () => {
    for (const bad of [null, '', false]) {
      assert.throws(() => retention.setDays(bad), (e) => e.status === 400, `value ${JSON.stringify(bad)}`);
    }
  });

  it('accepts the boundaries 0 and 3650', () => {
    assert.equal(retention.setDays(0), 0);
    assert.equal(retention.setDays(3650), 3650);
    assert.equal(retention.MAX_DAYS, 3650);
  });

  it('ignores a corrupt stored value (treated as keep forever)', () => {
    db.prepare("INSERT INTO settings (key, value) VALUES ('audit_retention_days', 'banana')").run();
    assert.equal(retention.getDays(), 0);
  });
});
