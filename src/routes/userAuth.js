const express = require('express');
const router = express.Router();
const domainsModule = require('../domains');
const ldap = require('../ldap');
const audit = require('../audit');
const logger = require('../logger');
const mailer = require('../mailer');
const duo = require('../duo');
const cryptoHelper = require('../crypto');
const { signUserToken, signMfaPendingToken, verifyToken, sessionCookieOptions, refreshSession } = require('../auth');
const sessionConfig = require('../sessionConfig');

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

// SameSite=Lax (not Strict) is required here: the browser leaves this site
// entirely to show Duo's hosted prompt, then Duo redirects it back via a
// top-level navigation. A Strict cookie would not be sent on that return
// trip, breaking the flow; Lax still is for a plain top-level GET redirect.
const MFA_PENDING_COOKIE_OPTS = {
  httpOnly: true,
  sameSite: 'lax',
  secure: process.env.COOKIE_SECURE === 'true',
  maxAge: 5 * 60 * 1000,
};

// Final step of a successful sign-in, whether or not MFA was involved: records
// the login, sends the (optional) success alert, and issues the session.
//
// The user's own credentials are cached (encrypted) inside their signed,
// httpOnly session cookie so later requests can perform directory
// operations as them - there is no separate stored service account.
// `bindDn` is the account's real distinguishedName, resolved during
// authentication; every subsequent LDAP bind in this session uses it
// directly, regardless of what identifier the person originally typed.
// Returns the session lifetime in seconds.
function completeLogin(req, res, { username, domain, bindDn, password, mfa }) {
  logger.info('user_login_success', { requestId: req.id, username, domain: domain.name, ip: req.ip, ...(mfa ? { mfa: true } : {}) });
  audit.logEvent(req, {
    domainId: domain.id, domainLabel: domain.name, eventType: 'login',
    actorUsername: username, success: true,
  });
  mailer.sendAlert({
    domainRow: domain, category: 'login_success',
    ...mailer.loginSuccessEmail({ username, domainName: domain.name, ip: req.ip, time: new Date().toISOString() }),
  });
  const ttl = sessionConfig.userTimeoutSeconds();
  const token = signUserToken({
    username, domainId: domain.id, pwd: cryptoHelper.encrypt(password), bindDn,
  }, ttl);
  res.cookie('user_token', token, sessionCookieOptions(ttl));
  return ttl;
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

  // Primary (AD) authentication succeeded. If MFA is enforced for this
  // domain, a full session is NOT issued yet - the person still has to
  // complete Duo before they're considered logged in.
  const effectiveDuo = duo.resolveEffective(domain);
  if (effectiveDuo.enforced) {
    if (!duo.isConfigured(effectiveDuo)) {
      // Fail closed: "enforced" must never silently become "skipped"
      // because an admin forgot to fill in the Duo application details.
      logger.error('duo_misconfigured', { requestId: req.id, username, domain: domain.name });
      audit.logEvent(req, {
        domainId: domain.id, domainLabel: domain.name, eventType: 'login',
        actorUsername: username, success: false, detail: 'MFA is enforced but not fully configured',
      });
      return res.status(503).json({ error: 'Multi-factor authentication is required but not configured correctly. Contact your administrator.' });
    }

    let authUrl, state;
    try {
      ({ authUrl, state } = await duo.startAuth(effectiveDuo, username));
    } catch (e) {
      logger.error('duo_start_auth_failed', { requestId: req.id, username, domain: domain.name, ...logger.errInfo(e) });
      audit.logEvent(req, {
        domainId: domain.id, domainLabel: domain.name, eventType: 'login',
        actorUsername: username, success: false, detail: 'Could not start MFA challenge',
      });
      return res.status(503).json({ error: 'Could not start multi-factor authentication. Please try again shortly.' });
    }

    const pendingToken = signMfaPendingToken({
      username, domainId: domain.id, bindDn: authorizedUser.dn,
      pwd: cryptoHelper.encrypt(password), state,
    });
    res.cookie('mfa_pending', pendingToken, MFA_PENDING_COOKIE_OPTS);
    logger.info('mfa_challenge_started', { requestId: req.id, username, domain: domain.name, ip: req.ip });
    audit.logEvent(req, {
      domainId: domain.id, domainLabel: domain.name, eventType: 'mfa_challenge',
      actorUsername: username, success: true,
    });
    return res.json({ ok: true, mfaRequired: true, redirectUrl: authUrl });
  }

  const ttl = completeLogin(req, res, { username, domain, bindDn: authorizedUser.dn, password });
  res.json({ ok: true, username, domain: domain.name, features: featuresFor(domain), sessionTimeoutSeconds: ttl });
});

// Duo redirects the browser back here after the person completes (or
// cancels/fails) the Universal Prompt. This is a plain top-level GET, not
// an API call the frontend makes directly, so on every outcome it redirects
// back into the user portal UI rather than returning JSON.
router.get('/duo-callback', async (req, res) => {
  const finish = (path) => res.redirect(302, path);

  const pending = req.cookies.mfa_pending && verifyToken(req.cookies.mfa_pending);
  res.clearCookie('mfa_pending', { sameSite: 'lax', secure: process.env.COOKIE_SECURE === 'true' });

  if (!pending || pending.role !== 'mfa_pending') {
    logger.warn('mfa_callback_no_pending_session', { requestId: req.id, ip: req.ip });
    return finish('/?error=mfa_session_expired');
  }

  const domain = domainsModule.getById(pending.domainId);
  if (!domain) {
    logger.error('mfa_callback_domain_missing', { requestId: req.id, username: pending.username });
    return finish('/?error=mfa_failed');
  }

  const mfaFailed = (detailLog, logFn, extra = {}) => {
    logger[logFn](detailLog, { requestId: req.id, username: pending.username, domain: domain.name, ip: req.ip, ...extra });
    audit.logEvent(req, {
      domainId: domain.id, domainLabel: domain.name, eventType: 'login',
      actorUsername: pending.username, success: false, detail: 'MFA verification failed',
    });
  };
  const mfaFailedAlert = () => mailer.sendAlert({
    domainRow: domain, category: 'login_failure',
    ...mailer.loginFailureEmail({ username: pending.username, domainName: domain.name, reason: 'MFA verification failed', ip: req.ip, time: new Date().toISOString() }),
  });

  if (req.query.error) {
    // Duo itself reported a problem (e.g. the person cancelled the prompt).
    mfaFailed('mfa_denied_by_duo', 'warn', { error: req.query.error });
    mfaFailedAlert();
    return finish('/?error=mfa_failed');
  }

  if (!req.query.state || req.query.state !== pending.state || !req.query.duo_code) {
    mfaFailed('mfa_callback_state_mismatch', 'warn');
    return finish('/?error=mfa_failed');
  }

  const effectiveDuo = duo.resolveEffective(domain);
  try {
    await duo.verifyAuth(effectiveDuo, req.query.duo_code, pending.username);
  } catch (e) {
    mfaFailed('mfa_verify_failed', 'warn', logger.errInfo(e));
    mfaFailedAlert();
    return finish('/?error=mfa_failed');
  }

  let password;
  try {
    password = cryptoHelper.decrypt(pending.pwd);
  } catch (e) {
    logger.error('mfa_callback_decrypt_failed', { requestId: req.id, username: pending.username, ...logger.errInfo(e) });
    return finish('/?error=mfa_session_expired');
  }

  completeLogin(req, res, { username: pending.username, domain, bindDn: pending.bindDn, password, mfa: true });
  return finish('/');
});

router.post('/logout', (req, res) => {
  const data = req.cookies.user_token && verifyToken(req.cookies.user_token);
  if (data && data.role === 'user') {
    const domain = domainsModule.getById(data.domainId);
    audit.logEvent(req, {
      domainId: data.domainId, domainLabel: domain ? domain.name : null, eventType: 'logout',
      actorUsername: data.username, success: true,
      detail: req.body && req.body.reason === 'timeout' ? 'Signed out automatically after session timeout' : null,
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
  const ttl = refreshSession(res, data);
  res.json({ username: data.username, domain: domain.name, features: featuresFor(domain), sessionTimeoutSeconds: ttl });
});

module.exports = router;
