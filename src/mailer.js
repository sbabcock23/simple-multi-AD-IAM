const db = require('./db');
const logger = require('./logger');
const cryptoHelper = require('./crypto');
const templates = require('./templates');

const SMTP_DEFAULTS = { host: '', port: 587, secure: false, tlsRejectUnauthorized: true, username: '', passwordEnc: '', from: '' };
const GLOBAL_DEFAULTS = { enabled: false, onLoginFailure: true, onAccountAction: true, recipients: [], smtp: { ...SMTP_DEFAULTS } };
const DOMAIN_DEFAULTS = { enabled: true, onLoginFailure: true, onAccountAction: true, recipients: [], smtpOverride: false, smtp: { ...SMTP_DEFAULTS } };

function mergeConfig(partial, defaults) {
  const p = partial && typeof partial === 'object' ? partial : {};
  return {
    ...defaults,
    ...p,
    recipients: Array.isArray(p.recipients) ? p.recipients : defaults.recipients,
    smtp: { ...defaults.smtp, ...(p.smtp && typeof p.smtp === 'object' ? p.smtp : {}) },
  };
}

function getGlobalConfig() {
  const row = db.prepare("SELECT value FROM settings WHERE key = 'alert_config'").get();
  let parsed = {};
  try { parsed = row ? JSON.parse(row.value) : {}; } catch (e) { parsed = {}; }
  return mergeConfig(parsed, GLOBAL_DEFAULTS);
}

function setGlobalConfig(config) {
  db.prepare(`INSERT INTO settings (key, value) VALUES ('alert_config', ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value`).run(JSON.stringify(config));
}

function getDomainConfig(domainRow) {
  // domainRow.alert_config may already be parsed (from src/domains.js) or a raw JSON string (from a fresh db row).
  let parsed = domainRow ? domainRow.alert_config : {};
  if (typeof parsed === 'string') {
    try { parsed = JSON.parse(parsed || '{}'); } catch (e) { parsed = {}; }
  }
  return mergeConfig(parsed, DOMAIN_DEFAULTS);
}

// Combines global + per-domain settings into the config actually used for a
// given event. Both the master switch and the specific trigger must be
// enabled at the global level AND (if a domain is involved) the domain
// level. Recipients and SMTP server can each be overridden independently
// per domain.
function resolveEffective(domainRow) {
  const g = getGlobalConfig();
  if (!domainRow) {
    return { enabled: g.enabled, onLoginFailure: g.onLoginFailure, onAccountAction: g.onAccountAction, recipients: g.recipients, smtp: g.smtp };
  }
  const d = getDomainConfig(domainRow);
  return {
    enabled: g.enabled && d.enabled,
    onLoginFailure: g.onLoginFailure && d.onLoginFailure,
    onAccountAction: g.onAccountAction && d.onAccountAction,
    recipients: d.recipients && d.recipients.length ? d.recipients : g.recipients,
    smtp: d.smtpOverride ? d.smtp : g.smtp,
  };
}

async function deliver(smtp, recipients, subject, text) {
  const nodemailer = require('nodemailer');
  const transporter = nodemailer.createTransport({
    host: smtp.host,
    port: Number(smtp.port) || 587,
    secure: !!smtp.secure,
    auth: smtp.username ? { user: smtp.username, pass: smtp.passwordEnc ? cryptoHelper.decrypt(smtp.passwordEnc) : '' } : undefined,
    tls: { rejectUnauthorized: !!smtp.tlsRejectUnauthorized },
  });
  await transporter.sendMail({
    from: smtp.from || smtp.username || 'no-reply@localhost',
    to: recipients.join(','),
    subject,
    text,
  });
}

// Fire-and-forget alert send: never throws, never blocks or slows down the
// request that triggered it. Failures are logged, not surfaced to the user.
function sendAlert({ domainRow, category, subject, text }) {
  (async () => {
    const cfg = resolveEffective(domainRow);
    if (!cfg.enabled) return;
    if (category === 'login_failure' && !cfg.onLoginFailure) return;
    if (category === 'account_action' && !cfg.onAccountAction) return;
    if (!cfg.recipients.length) { logger.debug('alert_skipped', { category, reason: 'no_recipients' }); return; }
    if (!cfg.smtp.host) { logger.debug('alert_skipped', { category, reason: 'no_smtp_host' }); return; }
    try {
      await deliver(cfg.smtp, cfg.recipients, subject, text);
      logger.info('alert_sent', { category, recipients: cfg.recipients.join(',') });
    } catch (e) {
      logger.error('alert_send_failed', { category, ...logger.errInfo(e) });
    }
  })().catch((e) => logger.error('alert_send_failed', { category, ...logger.errInfo(e) }));
}

async function sendTestEmail({ domainRow, overrideSmtp, overrideRecipients }) {
  let smtp; let recipients;
  if (overrideSmtp) {
    smtp = { ...SMTP_DEFAULTS, ...overrideSmtp };
    recipients = overrideRecipients && overrideRecipients.length ? overrideRecipients : resolveEffective(domainRow).recipients;
  } else {
    const cfg = resolveEffective(domainRow);
    smtp = cfg.smtp;
    recipients = cfg.recipients;
  }
  if (!recipients || !recipients.length) throw new Error('No recipient email addresses configured');
  if (!smtp.host) throw new Error('No SMTP host configured');
  await deliver(
    smtp,
    recipients,
    'IAM Self-Service test alert',
    'This is a test email from your IAM Self-Service portal.\n\nIf you received this, SMTP alerting is configured correctly.'
  );
  return { recipients };
}

function loginFailureEmail({ username, domainName, reason, ip, time }) {
  return templates.renderTemplate('login_failure', {
    username, domain: domainName || 'unrecognized', reason, ip: ip || 'unknown', time,
  });
}

function accountActionEmail({ actor, target, domainName, action, success, detail, ip, time }) {
  const actionLabel = action === 'unlock' ? 'Account unlock' : 'Password reset';
  return templates.renderTemplate('account_action', {
    action: actionLabel,
    result: success ? 'Success' : 'Failure',
    target, actor, domain: domainName, detail: detail || '', ip: ip || 'unknown', time,
  });
}

// Strips the encrypted password blob out of an SMTP config for API
// responses, replacing it with a boolean so the UI can show "a password is
// set" without ever re-transmitting the (encrypted) secret.
function sanitizeSmtp(smtp) {
  const { passwordEnc, ...rest } = smtp;
  return { ...rest, hasPassword: !!passwordEnc };
}

module.exports = {
  getGlobalConfig, setGlobalConfig, getDomainConfig, resolveEffective,
  sendAlert, sendTestEmail, loginFailureEmail, accountActionEmail, sanitizeSmtp,
  GLOBAL_DEFAULTS, DOMAIN_DEFAULTS,
};
