'use strict';
const { describe, it, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const { setupUnitEnv } = require('../helpers/env');

const env = setupUnitEnv();
const db = require('../../src/db');
const sc = require('../../src/sessionConfig');

describe('src/sessionConfig', () => {
  beforeEach(() => db.prepare("DELETE FROM settings WHERE key = 'session_config'").run());
  after(() => env.cleanup());

  it('has sane defaults (user 120 min, admin 480 min)', () => {
    assert.deepEqual(sc.get(), { userTimeoutMinutes: 120, adminTimeoutMinutes: 480 });
    assert.equal(sc.userTimeoutSeconds(), 7200);
    assert.equal(sc.adminTimeoutSeconds(), 28800);
  });

  it('persists independent values for each portal', () => {
    sc.set({ userTimeoutMinutes: 15, adminTimeoutMinutes: 60 });
    assert.deepEqual(sc.get(), { userTimeoutMinutes: 15, adminTimeoutMinutes: 60 });
    assert.equal(sc.userTimeoutSeconds(), 900);
  });

  it('accepts the inclusive boundaries 5 and 1440', () => {
    assert.doesNotThrow(() => sc.validate({ userTimeoutMinutes: 5, adminTimeoutMinutes: 1440 }));
  });

  for (const [label, input] of [
    ['below minimum', { userTimeoutMinutes: 4, adminTimeoutMinutes: 60 }],
    ['above maximum', { userTimeoutMinutes: 60, adminTimeoutMinutes: 1441 }],
    ['non-integer', { userTimeoutMinutes: 10.5, adminTimeoutMinutes: 60 }],
    ['non-numeric', { userTimeoutMinutes: 'abc', adminTimeoutMinutes: 60 }],
    ['missing field', { userTimeoutMinutes: 60 }],
    ['null', { userTimeoutMinutes: null, adminTimeoutMinutes: 60 }],
  ]) {
    it(`rejects ${label} with a 400-style error and stores nothing`, () => {
      assert.throws(() => sc.set(input), (e) => e.status === 400 && /minutes between 5 and 1440/.test(e.message));
      assert.deepEqual(sc.get(), { userTimeoutMinutes: 120, adminTimeoutMinutes: 480 });
    });
  }

  it('treats numeric strings as numbers', () => {
    assert.deepEqual(sc.set({ userTimeoutMinutes: '30', adminTimeoutMinutes: '45' }), { userTimeoutMinutes: 30, adminTimeoutMinutes: 45 });
  });

  it('clamps/repairs a corrupted stored value instead of crashing', () => {
    db.prepare("INSERT INTO settings (key, value) VALUES ('session_config', ?)").run(JSON.stringify({ userTimeoutMinutes: 99999, adminTimeoutMinutes: 'x' }));
    assert.deepEqual(sc.get(), { userTimeoutMinutes: 1440, adminTimeoutMinutes: 480 });
    db.prepare("UPDATE settings SET value = 'not json' WHERE key = 'session_config'").run();
    assert.deepEqual(sc.get(), { userTimeoutMinutes: 120, adminTimeoutMinutes: 480 });
  });
});
