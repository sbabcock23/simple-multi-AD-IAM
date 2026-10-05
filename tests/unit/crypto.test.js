'use strict';
const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const { TEST_ENCRYPTION_KEY } = require('../helpers/env');

process.env.ENCRYPTION_KEY = TEST_ENCRYPTION_KEY;
const { encrypt, decrypt } = require('../../src/crypto');

describe('src/crypto (AES-256-GCM secret storage)', () => {
  afterEach(() => { process.env.ENCRYPTION_KEY = TEST_ENCRYPTION_KEY; });

  it('round-trips ASCII, unicode and empty strings', () => {
    for (const s of ['hunter2', 'pässwörd-日本語-🔐', '', 'a'.repeat(10000)]) {
      assert.equal(decrypt(encrypt(s)), s);
    }
  });

  it('never stores plaintext in the ciphertext', () => {
    const secret = 'SuperSecretValue123';
    const enc = encrypt(secret);
    assert.ok(!enc.includes(secret));
    assert.ok(!Buffer.from(enc, 'base64').toString('utf8').includes(secret));
  });

  it('uses a fresh random IV so identical inputs give different ciphertexts', () => {
    assert.notEqual(encrypt('same'), encrypt('same'));
  });

  it('detects tampering (GCM auth tag)', () => {
    const buf = Buffer.from(encrypt('payload'), 'base64');
    buf[buf.length - 1] ^= 0xff;
    assert.throws(() => decrypt(buf.toString('base64')));
  });

  it('cannot be decrypted with a different ENCRYPTION_KEY', () => {
    const enc = encrypt('payload');
    process.env.ENCRYPTION_KEY = 'a-completely-different-key';
    assert.throws(() => decrypt(enc));
  });

  it('accepts keys of any length (derived to 32 bytes)', () => {
    for (const k of ['x', 'k'.repeat(500)]) {
      process.env.ENCRYPTION_KEY = k;
      assert.equal(decrypt(encrypt('ok')), 'ok');
    }
  });

  it('coerces non-string input to string', () => {
    assert.equal(decrypt(encrypt(12345)), '12345');
  });
});
