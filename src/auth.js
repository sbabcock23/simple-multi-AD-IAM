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

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return null;
  }
}

module.exports = { hashPassword, verifyPassword, signAdminToken, signUserToken, verifyToken };
