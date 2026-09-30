const express = require('express');
const router = express.Router();
const db = require('../db');
const logger = require('../logger');
const { verifyPassword, signAdminToken, verifyToken, sessionCookieOptions, refreshSession } = require('../auth');
const sessionConfig = require('../sessionConfig');

router.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  const row = db.prepare('SELECT * FROM admin_users WHERE username = ?').get(username);
  if (!row || !verifyPassword(password, row.password_hash)) {
    logger.warn('admin_login_failed', { requestId: req.id, username, ip: req.ip });
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const ttl = sessionConfig.adminTimeoutSeconds();
  const token = signAdminToken({ id: row.id, username: row.username }, ttl);
  res.cookie('admin_token', token, sessionCookieOptions(ttl));
  logger.info('admin_login_success', { requestId: req.id, username: row.username, ip: req.ip });
  res.json({ ok: true, username: row.username, sessionTimeoutSeconds: ttl });
});

router.post('/logout', (req, res) => {
  res.clearCookie('admin_token');
  res.json({ ok: true });
});

router.get('/me', (req, res) => {
  const data = req.cookies.admin_token && verifyToken(req.cookies.admin_token);
  if (!data || data.role !== 'admin') {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  const ttl = refreshSession(res, data);
  res.json({ username: data.username, sessionTimeoutSeconds: ttl });
});

module.exports = router;
