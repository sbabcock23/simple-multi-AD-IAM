const express = require('express');
const router = express.Router();
const domainsModule = require('../domains');
const ldap = require('../ldap');
const audit = require('../audit');
const logger = require('../logger');
const mailer = require('../mailer');
const cryptoHelper = require('../crypto');
const { signUserToken, verifyToken } = require('../auth');

function featuresFor(domain) {
  return {
    unlock: !!domain.feature_unlock,
    reset: !!domain.feature_reset,
    forceChange: !!domain.feature_force_change,
  };
}

const REASON_MESSAGES = {
  NO_ALLOWED_GROUPS: 'no_allowed_groups_configured',
  NOT_AUTHORIZED: 'not_a_member_of_an_allowed_group',
};

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
    mailer.sendAlert({
      domainRow: null, category: 'login_failure',
      ...mailer.loginFailureEmail({ username, domainName: null, reason: 'Domain not configured for self-service access', ip: req.ip, time: new Date().toISOString() }),
    });
    return res.status(401).json({ error: 'That domain is not configured for self-service access' });
  }

  // Users may sign in with their userPrincipalName, their email address, or
  // (when the domain has a NetBIOS name configured) their sAMAccountName -
  // and their account must belong to one of the domain's allowed AD groups
  // (nested membership included), not just have a valid password.
  let authorizedUser;
  try {
    authorizedUser = await ldap.authenticateAndAuthorize(domain, username, password, domain.allowed_groups);
  } catch (e) {
    const reason = REASON_MESSAGES[e.code] || 'invalid_credentials_or_unreachable';
    logger.warn('user_login_failed', {
      requestId: req.id, username, domain: domain.name, reason, ip: req.ip, ...logger.errInfo(e),
    });
    audit.logEvent(req, {
      domainId: domain.id, domainLabel: domain.name, eventType: 'login',
      actorUsername: username, success: false, detail: reason,
    });
    mailer.sendAlert({
      domainRow: domain, category: 'login_failure',
      ...mailer.loginFailureEmail({ username, domainName: domain.name, reason, ip: req.ip, time: new Date().toISOString() }),
    });
    // Deliberately generic - doesn't reveal whether the password was wrong,
    // the account doesn't exist, or it exists but isn't in an allowed group.
    return res.status(401).json({ error: 'Invalid username or password, or your account is not authorized to use this portal.' });
  }

  logger.info('user_login_success', { requestId: req.id, username, domain: domain.name, ip: req.ip });
  audit.logEvent(req, {
    domainId: domain.id, domainLabel: domain.name, eventType: 'login',
    actorUsername: username, success: true,
  });

  // The user's own credentials are cached (encrypted) inside their signed,
  // httpOnly session cookie so later requests can perform directory
  // operations as them - there is no separate stored service account.
  // `bindDn` is the account's real distinguishedName, resolved during
  // authentication; every subsequent LDAP bind in this session uses it
  // directly, regardless of what identifier the person originally typed.
  const token = signUserToken({
    username, domainId: domain.id, pwd: cryptoHelper.encrypt(password), bindDn: authorizedUser.dn,
  });
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
