const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'insecure-dev-secret-change-me';

function hashPassword(password) {
  return bcrypt.hashSync(password, 12);
}

function verifyPassword(password, hash) {
  return bcrypt.compareSync(password, hash);
}

function signAdminToken(payload) {
  return jwt.sign({ ...payload, role: 'admin' }, JWT_SECRET, { expiresIn: '8h' });
}

function signUserToken(payload) {
  return jwt.sign({ ...payload, role: 'user' }, JWT_SECRET, { expiresIn: '2h' });
}

// Short-lived token representing "primary (AD) authentication succeeded,
// Duo verification is still pending". Deliberately a distinct role/shape
// from the full user session token so a login can never be treated as
// complete until Duo confirms - and it expires quickly since it only needs
// to survive the round trip through Duo's hosted prompt.
function signMfaPendingToken(payload) {
  return jwt.sign({ ...payload, role: 'mfa_pending' }, JWT_SECRET, { expiresIn: '5m' });
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return null;
  }
}

module.exports = { hashPassword, verifyPassword, signAdminToken, signUserToken, signMfaPendingToken, verifyToken };
