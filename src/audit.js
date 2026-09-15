const db = require('./db');
const logger = require('./logger');

function isGlobalAuditEnabled() {
  const row = db.prepare("SELECT value FROM settings WHERE key = 'audit_logging_enabled'").get();
  return !row || row.value === '1';
}

function isDomainAuditEnabled(domainId) {
  if (!domainId) return true; // no domain matched, so only the global switch applies
  const row = db.prepare('SELECT audit_enabled FROM domains WHERE id = ?').get(domainId);
  return !row || !!row.audit_enabled;
}

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return String(forwarded).split(',')[0].trim();
  return (req.socket && req.socket.remoteAddress) || req.ip || '';
}

// eventType: 'login' | 'logout' | 'search' | 'unlock' | 'reset_password'
function logEvent(req, { domainId = null, domainLabel = null, eventType, actorUsername, targetIdentifier = null, success, detail = null }) {
  try {
    if (!isGlobalAuditEnabled()) return;
    if (!isDomainAuditEnabled(domainId)) return;
    db.prepare(`INSERT INTO audit_log
        (created_at, domain_id, domain_label, event_type, actor_username, target_identifier, success, detail, ip_address)
      VALUES (?,?,?,?,?,?,?,?,?)`).run(
      new Date().toISOString(),
      domainId,
      domainLabel,
      eventType,
      actorUsername,
      targetIdentifier,
      success ? 1 : 0,
      detail,
      getClientIp(req)
    );
  } catch (e) {
    // Auditing must never break the underlying request, but a failure here
    // (e.g. disk full, DB locked) is worth knowing about.
    logger.error('audit_write_failed', { eventType, actorUsername, ...logger.errInfo(e) });
  }
}

module.exports = { logEvent, isGlobalAuditEnabled, isDomainAuditEnabled, getClientIp };
