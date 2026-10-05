'use strict';
const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const { setupUnitEnv } = require('../helpers/env');

const env = setupUnitEnv();
const prefs = require('../../src/preferences');

describe('src/preferences (theme)', () => {
  after(() => env.cleanup());

  it('returns null until a theme is chosen', () => {
    assert.equal(prefs.getTheme('user', 'nobody@x.test'), null);
  });

  it('stores and updates light/dark', () => {
    assert.equal(prefs.setTheme('user', 'a@x.test', 'dark'), 'dark');
    assert.equal(prefs.getTheme('user', 'a@x.test'), 'dark');
    prefs.setTheme('user', 'a@x.test', 'light');
    assert.equal(prefs.getTheme('user', 'a@x.test'), 'light');
  });

  it('rejects any other value with a 400-style error', () => {
    for (const bad of ['blue', '', undefined, null, 'DARK', 1]) {
      assert.throws(() => prefs.setTheme('user', 'a@x.test', bad), (e) => e.status === 400);
    }
  });

  it('matches usernames case-insensitively and ignores surrounding whitespace', () => {
    prefs.setTheme('user', '  Mixed@X.Test ', 'dark');
    assert.equal(prefs.getTheme('user', 'mixed@x.test'), 'dark');
  });

  it('keeps the user and admin portals separate even for the same name', () => {
    prefs.setTheme('admin', 'same', 'dark');
    prefs.setTheme('user', 'same', 'light');
    assert.equal(prefs.getTheme('admin', 'same'), 'dark');
    assert.equal(prefs.getTheme('user', 'same'), 'light');
  });
});
