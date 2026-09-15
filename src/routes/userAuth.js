const express = require('express');
const router = express.Router();
const domainsModule = require('../domains');
const ldap = require('../ldap');
const audit = require('../audit');
const logger = require('../logger');
const cryptoHelper = require('../crypto');
const { signUserToken, verifyToken } = require('../auth');

function featuresFor(domain) {
  return {
    unlock: !!domain.feature_unlock,
    reset: !!domain.feature_reset,
    forceChange: !!domain.feature_force_change,
  };
}

router.post('/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password || !username.includes('@')) {
    return res.status(400).json({ error: 'Enter your username as username@domain' });
  }

  const suffix = username.split('@')[1].toLowerCase();
  const domain = domainsModule.getBySuffix(suffix);

  if (!domain) {
    logger.warn('user_login_failed', { requestId: req.id, username, reason: 'domain_not_configured', suffix, ip: req.ip });
    audit.logEvent(req, {
      domainId: null, domainLabel: suffix, eventType: 'login',
      actorUsername: username, success: false, detail: 'Domain not configured for self-service access',
    });
    return res.status(401).json({ error: 'That domain is not configured for self-service access' });
  }

  try {
    await ldap.authenticateUser(domain, username, password);
  } catch (e) {
    // Log the real LDAP failure reason server-side (wrong password, LDAP
    // server unreachable, TLS error, etc.) - the client only ever sees a
    // generic message, on purpose, so as not to leak which part failed.
    logger.warn('user_login_failed', {
      requestId: req.id, username, domain: domain.name, reason: 'ldap_bind_failed', ip: req.ip,
      ...logger.errInfo(e),
    });
    audit.logEvent(req, {
      domainId: domain.id, domainLabel: domain.name, eventType: 'login',
      actorUsername: username, success: false, detail: 'Invalid credentials',
    });
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  logger.info('user_login_success', { requestId: req.id, username, domain: domain.name, ip: req.ip });
  audit.logEvent(req, {
    domainId: domain.id, domainLabel: domain.name, eventType: 'login',
    actorUsername: username, success: true,
  });

  // The user's own credentials are cached (encrypted) inside their signed,
  // httpOnly session cookie so later requests can perform directory
  // operations as them - there is no separate stored service account.
  const token = signUserToken({ username, domainId: domain.id, pwd: cryptoHelper.encrypt(password) });
  res.cookie('user_token', token, {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.COOKIE_SECURE === 'true',
    maxAge: 2 * 60 * 60 * 1000,
  });
  res.json({ ok: true, username, domain: domain.name, features: featuresFor(domain) });
});

router.post('/logout', (req, res) => {
  const data = req.cookies.user_token && verifyToken(req.cookies.user_token);
  if (data && data.role === 'user') {
    const domain = domainsModule.getById(data.domainId);
    audit.logEvent(req, {
      domainId: data.domainId, domainLabel: domain ? domain.name : null, eventType: 'logout',
      actorUsername: data.username, success: true,
    });
  }
  res.clearCookie('user_token');
  res.json({ ok: true });
});

router.get('/me', (req, res) => {
  const data = req.cookies.user_token && verifyToken(req.cookies.user_token);
  if (!data || data.role !== 'user') {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  const domain = domainsModule.getById(data.domainId);
  if (!domain || !domain.enabled) {
    return res.status(401).json({ error: 'Domain disabled' });
  }
  res.json({ username: data.username, domain: domain.name, features: featuresFor(domain) });
});

module.exports = router;
