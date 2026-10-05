'use strict';
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { setupUnitEnv, TEST_JWT_SECRET } = require('../helpers/env');

const env = setupUnitEnv();
const auth = require('../../src/auth');
const sessionConfig = require('../../src/sessionConfig');

describe('src/auth', () => {
  after(() => env.cleanup());

  describe('password hashing', () => {
    it('verifies the right password and rejects the wrong one', () => {
      const h = auth.hashPassword('Correct-Horse-1');
      assert.ok(auth.verifyPassword('Correct-Horse-1', h));
      assert.ok(!auth.verifyPassword('correct-horse-1', h));
      assert.ok(!auth.verifyPassword('', h));
    });

    it('salts: hashing the same password twice gives different hashes', () => {
      assert.notEqual(auth.hashPassword('same'), auth.hashPassword('same'));
    });

    it('does not contain the plaintext', () => {
      assert.ok(!auth.hashPassword('PlainTextPw!').includes('PlainTextPw!'));
    });
  });

  describe('tokens', () => {
    it('admin and user tokens carry distinct roles', () => {
      assert.equal(auth.verifyToken(auth.signAdminToken({ username: 'a' })).role, 'admin');
      assert.equal(auth.verifyToken(auth.signUserToken({ username: 'u' })).role, 'user');
      assert.equal(auth.verifyToken(auth.signMfaPendingToken({ username: 'u' })).role, 'mfa_pending');
    });

    it('a caller cannot smuggle a different role in via the payload', () => {
      const t = auth.verifyToken(auth.signUserToken({ username: 'u', role: 'admin' }));
      assert.equal(t.role, 'user');
      const a = auth.verifyToken(auth.signAdminToken({ username: 'u', role: 'user' }));
      assert.equal(a.role, 'admin');
    });

    it('defaults token lifetime to the configured session timeout', () => {
      const t = auth.verifyToken(auth.signUserToken({ username: 'u' }));
      assert.equal(t.exp - t.iat, sessionConfig.userTimeoutSeconds());
      const a = auth.verifyToken(auth.signAdminToken({ username: 'a' }));
      assert.equal(a.exp - a.iat, sessionConfig.adminTimeoutSeconds());
    });

    it('MFA-pending tokens live five minutes', () => {
      const t = auth.verifyToken(auth.signMfaPendingToken({ username: 'u' }));
      assert.equal(t.exp - t.iat, 300);
    });

    it('verifyToken returns null for garbage, tampered, wrong-secret and expired tokens', () => {
      assert.equal(auth.verifyToken('garbage'), null);
      assert.equal(auth.verifyToken(undefined), null);
      const good = auth.signUserToken({ username: 'u' });
      const [h, p, s] = good.split('.');
      const forgedPayload = Buffer.from(JSON.stringify({ username: 'u', role: 'admin' })).toString('base64url');
      assert.equal(auth.verifyToken(`${h}.${forgedPayload}.${s}`), null);
      assert.equal(auth.verifyToken(jwt.sign({ role: 'admin' }, 'other-secret', { expiresIn: 60 })), null);
      assert.equal(auth.verifyToken(jwt.sign({ role: 'user' }, TEST_JWT_SECRET, { expiresIn: -10 })), null);
    });
  });

  describe('session cookies', () => {
    it('are httpOnly + SameSite=Strict, and Secure only when COOKIE_SECURE=true', () => {
      process.env.COOKIE_SECURE = 'false';
      let o = auth.sessionCookieOptions(60);
      assert.equal(o.httpOnly, true);
      assert.equal(o.sameSite, 'strict');
      assert.equal(o.secure, false);
      assert.equal(o.maxAge, 60000);
      process.env.COOKIE_SECURE = 'true';
      o = auth.sessionCookieOptions(60);
      assert.equal(o.secure, true);
      process.env.COOKIE_SECURE = 'false';
    });

    it('refreshSession re-issues a fresh cookie, strips iat/exp and advertises the timeout', () => {
      const original = auth.verifyToken(auth.signUserToken({ username: 'u', domainId: 3 }));
      const calls = { cookie: null, headers: {} };
      const res = {
        cookie: (name, value, opts) => { calls.cookie = { name, value, opts }; },
        setHeader: (k, v) => { calls.headers[k] = v; },
      };
      const ttl = auth.refreshSession(res, original);
      assert.equal(ttl, sessionConfig.userTimeoutSeconds());
      assert.equal(calls.cookie.name, 'user_token');
      assert.equal(calls.headers['X-Session-Timeout'], String(ttl));
      const reissued = auth.verifyToken(calls.cookie.value);
      assert.equal(reissued.username, 'u');
      assert.equal(reissued.domainId, 3);
      assert.equal(reissued.exp - reissued.iat, ttl);
    });

    it('refreshSession uses the admin cookie name and admin timeout for admin tokens', () => {
      const original = auth.verifyToken(auth.signAdminToken({ username: 'a' }));
      let name; let header;
      auth.refreshSession({ cookie: (n) => { name = n; }, setHeader: (k, v) => { header = v; } }, original);
      assert.equal(name, 'admin_token');
      assert.equal(header, String(sessionConfig.adminTimeoutSeconds()));
    });
  });
});
