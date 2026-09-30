const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const sessionConfig = require('./sessionConfig');

const JWT_SECRET = process.env.JWT_SECRET || 'insecure-dev-secret-change-me';
const COOKIE_TOKEN_SECRET = process.env.COOKIE_TOKEN_SECRET || 'insecure-dev-cookie-secret-change-me';
const COOKIE_TOKEN_KEY = crypto.createHash('sha256').update(COOKIE_TOKEN_SECRET).digest();

function encryptCookieToken(token) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', COOKIE_TOKEN_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(token, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString('base64')}.${tag.toString('base64')}.${encrypted.toString('base64')}`;
}

function decryptCookieToken(value) {
  const parts = String(value || '').split('.');
  if (parts.length !== 3) throw new Error('Invalid encrypted token format');
  const iv = Buffer.from(parts[0], 'base64');
  const tag = Buffer.from(parts[1], 'base64');
  const encrypted = Buffer.from(parts[2], 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', COOKIE_TOKEN_KEY, iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return decrypted.toString('utf8');
}

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
  const encryptedToken = encryptCookieToken(token);
  res.cookie(isAdmin ? 'admin_token' : 'user_token', encryptedToken, sessionCookieOptions(ttl));
  res.setHeader('X-Session-Timeout', String(ttl));
  return ttl;
}

function verifyToken(token) {
  try {
    const decryptedToken = decryptCookieToken(token);
    return jwt.verify(decryptedToken, JWT_SECRET);
  } catch (e) {
    return null;
  }
}

module.exports = { hashPassword, verifyPassword, signAdminToken, signUserToken, verifyToken, sessionCookieOptions, refreshSession };
