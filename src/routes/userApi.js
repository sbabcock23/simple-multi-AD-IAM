const express = require('express');
const router = express.Router();
const db = require('../db');
const domainsModule = require('../domains');
const ldap = require('../ldap');
const audit = require('../audit');
const logger = require('../logger');

function getDomainForReq(req) {
  const domain = domainsModule.getById(req.user.domainId);
  if (!domain || !domain.enabled) {
    throw Object.assign(new Error('Your domain is currently disabled'), { status: 403 });
  }
  return domain;
}

// The signed-in user's own history of logins and actions - current session
// and past ones - so they can see exactly what was done under their account.
router.get('/audit', (req, res) => {
  const rows = db.prepare(
    'SELECT * FROM audit_log WHERE actor_username = ? ORDER BY created_at DESC LIMIT 200'
  ).all(req.user.username);
  res.json(rows);
});

router.get('/search', async (req, res) => {
  let domain;
  const q = (req.query.q || '').trim();
  try {
    domain = getDomainForReq(req);
    if (q.length < 2) return res.json([]);
    const results = await ldap.searchUsers(domain, req.user.username, req.user.password, q);
    audit.logEvent(req, {
      domainId: domain.id, domainLabel: domain.name, eventType: 'search',
      actorUsername: req.user.username, targetIdentifier: q, success: true,
    });
    res.json(results);
  } catch (e) {
    logger.error('search_failed', {
      requestId: req.id, actor: req.user.username, query: q, ...logger.errInfo(e),
    });
    audit.logEvent(req, {
      domainId: domain ? domain.id : req.user.domainId, domainLabel: domain ? domain.name : null,
      eventType: 'search', actorUsername: req.user.username, targetIdentifier: q,
      success: false, detail: e.message,
    });
    res.status(e.status || 500).json({ error: e.message, requestId: req.id });
  }
});

router.get('/:id', async (req, res) => {
  try {
    const domain = getDomainForReq(req);
    const user = await ldap.getUserByIdentifier(domain, req.user.username, req.user.password, req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (e) {
    logger.error('lookup_failed', {
      requestId: req.id, actor: req.user.username, target: req.params.id, ...logger.errInfo(e),
    });
    res.status(e.status || 500).json({ error: e.message, requestId: req.id });
  }
});

router.post('/:id/unlock', async (req, res) => {
  let domain;
  try {
    domain = getDomainForReq(req);
    if (!domain.feature_unlock) {
      throw Object.assign(new Error('Account unlock is disabled for this domain'), { status: 403 });
    }
    const user = await ldap.getUserByIdentifier(domain, req.user.username, req.user.password, req.params.id);
    if (!user) throw Object.assign(new Error('User not found'), { status: 404 });
    await ldap.unlockUser(domain, req.user.username, req.user.password, user.dn);
    logger.info('unlock_success', { requestId: req.id, actor: req.user.username, target: req.params.id, domain: domain.name });
    audit.logEvent(req, {
      domainId: domain.id, domainLabel: domain.name, eventType: 'unlock',
      actorUsername: req.user.username, targetIdentifier: req.params.id, success: true,
    });
    res.json({ ok: true });
  } catch (e) {
    logger.error('unlock_failed', {
      requestId: req.id, actor: req.user.username, target: req.params.id,
      domain: domain ? domain.name : null, ...logger.errInfo(e),
    });
    audit.logEvent(req, {
      domainId: domain ? domain.id : req.user.domainId, domainLabel: domain ? domain.name : null,
      eventType: 'unlock', actorUsername: req.user.username, targetIdentifier: req.params.id,
      success: false, detail: e.message,
    });
    res.status(e.status || 500).json({ error: e.message, requestId: req.id });
  }
});

router.post('/:id/reset-password', async (req, res) => {
  let domain;
  try {
    domain = getDomainForReq(req);
    if (!domain.feature_reset) {
      throw Object.assign(new Error('Password reset is disabled for this domain'), { status: 403 });
    }
    const { newPassword, forceChange } = req.body || {};
    if (!newPassword || newPassword.length < 8) {
      throw Object.assign(new Error('Password must be at least 8 characters'), { status: 400 });
    }
    const user = await ldap.getUserByIdentifier(domain, req.user.username, req.user.password, req.params.id);
    if (!user) throw Object.assign(new Error('User not found'), { status: 404 });
    await ldap.resetPassword(domain, req.user.username, req.user.password, user.dn, newPassword, !!forceChange && !!domain.feature_force_change);
    logger.info('reset_password_success', { requestId: req.id, actor: req.user.username, target: req.params.id, domain: domain.name });
    audit.logEvent(req, {
      domainId: domain.id, domainLabel: domain.name, eventType: 'reset_password',
      actorUsername: req.user.username, targetIdentifier: req.params.id, success: true,
    });
    res.json({ ok: true });
  } catch (e) {
    logger.error('reset_password_failed', {
      requestId: req.id, actor: req.user.username, target: req.params.id,
      domain: domain ? domain.name : null, ...logger.errInfo(e),
    });
    audit.logEvent(req, {
      domainId: domain ? domain.id : req.user.domainId, domainLabel: domain ? domain.name : null,
      eventType: 'reset_password', actorUsername: req.user.username, targetIdentifier: req.params.id,
      success: false, detail: e.message,
    });
    res.status(e.status || 500).json({ error: e.message, requestId: req.id });
  }
});

module.exports = router;
