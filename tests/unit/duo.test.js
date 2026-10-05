'use strict';
const { describe, it, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const { setupUnitEnv } = require('../helpers/env');

const env = setupUnitEnv();
const db = require('../../src/db');
const duo = require('../../src/duo');
const cryptoHelper = require('../../src/crypto');

const creds = (over = {}) => ({
  clientId: 'DIABCDEFGHIJKLMNOPQR', clientSecretEnc: cryptoHelper.encrypt('s'.repeat(40)),
  apiHostname: 'api-1234abcd.duosecurity.com', redirectUrl: 'https://iam.example.test/api/auth/duo-callback', ...over,
});

describe('src/duo', () => {
  beforeEach(() => db.prepare("UPDATE settings SET value = '{}' WHERE key = 'duo_config'").run());
  after(() => env.cleanup());

  it('MFA is disabled by default', () => {
    assert.equal(duo.getGlobalConfig().mode, 'disabled');
    assert.equal(duo.resolveEffective(null).enforced, false);
    assert.equal(duo.resolveEffective({ duo_config: {} }).enforced, false);
  });

  describe('enforcement precedence', () => {
    it('inherit follows the global mode', () => {
      duo.setGlobalConfig({ ...duo.GLOBAL_DEFAULTS, mode: 'enforced' });
      assert.equal(duo.resolveEffective({ duo_config: { mode: 'inherit' } }).enforced, true);
      duo.setGlobalConfig({ ...duo.GLOBAL_DEFAULTS, mode: 'disabled' });
      assert.equal(duo.resolveEffective({ duo_config: { mode: 'inherit' } }).enforced, false);
    });

    it('a domain can force MFA on even when global is off', () => {
      assert.equal(duo.resolveEffective({ duo_config: { mode: 'enforced' } }).enforced, true);
    });

    it('a domain can opt out when global is enforced', () => {
      duo.setGlobalConfig({ ...duo.GLOBAL_DEFAULTS, mode: 'enforced' });
      assert.equal(duo.resolveEffective({ duo_config: { mode: 'disabled' } }).enforced, false);
    });

    it('parses duo_config given as a JSON string; corrupt JSON behaves as inherit', () => {
      assert.equal(duo.resolveEffective({ duo_config: JSON.stringify({ mode: 'enforced' }) }).enforced, true);
      assert.equal(duo.resolveEffective({ duo_config: '{{' }).enforced, false);
    });
  });

  describe('credential selection', () => {
    it('uses the global Duo app unless the domain opts into its own', () => {
      duo.setGlobalConfig({ ...duo.GLOBAL_DEFAULTS, ...creds({ clientId: 'GLOBAL' }) });
      const dom = { duo_config: { mode: 'enforced', credentialsOverride: false, ...creds({ clientId: 'DOMAIN' }) } };
      assert.equal(duo.resolveEffective(dom).clientId, 'GLOBAL');
      dom.duo_config.credentialsOverride = true;
      assert.equal(duo.resolveEffective(dom).clientId, 'DOMAIN');
    });

    it('decrypts the stored client secret for use', () => {
      duo.setGlobalConfig({ ...duo.GLOBAL_DEFAULTS, ...creds() });
      assert.equal(duo.resolveEffective(null).clientSecret, 's'.repeat(40));
    });
  });

  describe('isConfigured', () => {
    const full = { clientId: 'a', clientSecret: 'b', apiHostname: 'c', redirectUrl: 'd' };
    it('needs all four values', () => {
      assert.equal(duo.isConfigured(full), true);
      for (const k of Object.keys(full)) assert.equal(duo.isConfigured({ ...full, [k]: '' }), false, `missing ${k}`);
    });
  });

  describe('sanitize', () => {
    it('hides the encrypted secret behind hasClientSecret', () => {
      const s = duo.sanitize({ mode: 'enforced', clientId: 'x', clientSecretEnc: 'enc' });
      assert.equal(s.hasClientSecret, true);
      assert.ok(!('clientSecretEnc' in s));
      assert.equal(duo.sanitize({ clientSecretEnc: '' }).hasClientSecret, false);
    });
  });

  describe('healthCheck host validation (fails before any network call)', () => {
    for (const host of ['admin-1234abcd.duosecurity.com', 'example.com', 'api-xyz.evil.com', '', 'api-.duosecurity.com']) {
      it(`rejects "${host}"`, async () => {
        await assert.rejects(duo.healthCheck({ apiHostname: host }), /doesn't look like a Duo API hostname/);
      });
    }
  });
});
