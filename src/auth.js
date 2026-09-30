const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const sessionConfig = require('./sessionConfig');

const JWT_SECRET = process.env.JWT_SECRET || 'insecure-dev-secret-change-me';

function hashPassword(password) {
  return bcrypt.hashSync(password, 12);
}

function verifyPassword(password, hash) {
  return bcrypt.compareSync(password, hash);
}

// Token lifetimes come from the admin-configurable session timeouts
// (independent for the user and admin portals); the fallbacks are only used
// if a caller doesn't pass one.
function signAdminToken(payload, ttlSeconds = sessionConfig.adminTimeoutSeconds()) {
  return jwt.sign({ ...payload, role: 'admin' }, JWT_SECRET, { expiresIn: ttlSeconds });
}

function signUserToken(payload, ttlSeconds = sessionConfig.userTimeoutSeconds()) {
  return jwt.sign({ ...payload, role: 'user' }, JWT_SECRET, { expiresIn: ttlSeconds });
}

function sessionCookieOptions(ttlSeconds) {
  return {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.COOKIE_SECURE === 'true',
    maxAge: ttlSeconds * 1000,
  };
}

// Sliding (inactivity) session: every authenticated request re-issues the
// cookie with a fresh expiry, using the timeout currently configured for
// that portal. The lifetime in seconds is also advertised in a response
// header so the browser's own idle timer stays in step with the server.
function refreshSession(res, tokenData) {
  const { iat, exp, ...payload } = tokenData;
  const isAdmin = tokenData.role === 'admin';
  const ttl = isAdmin ? sessionConfig.adminTimeoutSeconds() : sessionConfig.userTimeoutSeconds();
  const token = isAdmin ? signAdminToken(payload, ttl) : signUserToken(payload, ttl);
  res.cookie(isAdmin ? 'admin_token' : 'user_token', token, sessionCookieOptions(ttl));
  res.setHeader('X-Session-Timeout', String(ttl));
  return ttl;
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return null;
  }
}

module.exports = { hashPassword, verifyPassword, signAdminToken, signUserToken, verifyToken, sessionCookieOptions, refreshSession };
