const express = require('express');
const router = express.Router();
const db = require('../db');
const domainsModule = require('../domains');
const ldap = require('../ldap');
const logger = require('../logger');
const mailer = require('../mailer');
const templates = require('../templates');
const cryptoHelper = require('../crypto');
const { hashPassword } = require('../auth');

function parseJsonArray(json, fallback) {
  try {
    const arr = JSON.parse(json || 'null');
    return Array.isArray(arr) ? arr : fallback;
  } catch (e) {
    return fallback;
  }
}

function parseJsonObject(json) {
  try {
    const parsed = JSON.parse(json || '{}');
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch (e) {
    return {};
  }
}

function domainPublic(row) {
  const rawAlert = parseJsonObject(row.alert_config);
  const mergedAlert = {
    ...mailer.DOMAIN_DEFAULTS,
    ...rawAlert,
    smtp: { ...mailer.DOMAIN_DEFAULTS.smtp, ...(rawAlert.smtp || {}) },
  };
  return {
    id: row.id,
    name: row.name,
    domain_suffix: row.domain_suffix,
    ldap_urls: parseJsonArray(row.ldap_urls, []),
    base_dn: row.base_dn,
    netbios_name: row.netbios_name || '',
    lookup_bind_dn: row.lookup_bind_dn || '',
    has_lookup_password: !!row.lookup_bind_password_enc,
    allowed_groups: parseJsonArray(row.allowed_groups, ['Domain Admins']),
    tls_reject_unauthorized: !!row.tls_reject_unauthorized,
    feature_unlock: !!row.feature_unlock,
    feature_reset: !!row.feature_reset,
    feature_force_change: !!row.feature_force_change,
    audit_enabled: !!row.audit_enabled,
    alert_config: { ...mergedAlert, smtp: mailer.sanitizeSmtp(mergedAlert.smtp) },
    enabled: !!row.enabled,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

function normalizeStringArray(input) {
  const arr = Array.isArray(input) ? input : [];
  return arr.map((u) => String(u).trim()).filter(Boolean);
}

function validateUrls(urls) {
  if (!urls.length) return 'At least one LDAP server is required';
  for (const u of urls) {
    if (!/^ldaps?:\/\/.+/i.test(u)) return `"${u}" is not a valid ldap:// or ldaps:// URL`;
  }
  return null;
}

// Builds the JSON to store in domains.alert_config, merging the submitted
// partial config over whatever was already stored, and only re-encrypting
// the SMTP password if a new one was actually typed (an empty/omitted
// password field means "leave the existing one alone").
function buildDomainAlertConfig(input, existingJson) {
  const existing = parseJsonObject(existingJson);
  const merged = {
    ...mailer.DOMAIN_DEFAULTS,
    ...existing,
    ...(input || {}),
    smtp: { ...mailer.DOMAIN_DEFAULTS.smtp, ...(existing.smtp || {}), ...((input && input.smtp) || {}) },
  };
  merged.recipients = normalizeStringArray(merged.recipients);
  const providedPassword = input && input.smtp && input.smtp.password;
  merged.smtp.passwordEnc = providedPassword
    ? cryptoHelper.encrypt(providedPassword)
    : ((existing.smtp && existing.smtp.passwordEnc) || '');
  delete merged.smtp.password;
  return merged;
}

// ---------- Domains ----------

router.get('/domains', (req, res) => {
  const rows = db.prepare('SELECT * FROM domains ORDER BY name').all();
  res.json(rows.map(domainPublic));
});

router.post('/domains', (req, res) => {
  const {
    name, domain_suffix, ldap_urls, base_dn, netbios_name, allowed_groups, alert_config,
    lookup_bind_dn, lookup_bind_password,
    tls_reject_unauthorized = true, feature_unlock = true, feature_reset = true,
    feature_force_change = true, audit_enabled = true, enabled = true,
  } = req.body || {};

  const urls = normalizeStringArray(ldap_urls);
  const urlError = validateUrls(urls);
  if (!name || !domain_suffix || !base_dn || urlError) {
    return res.status(400).json({ error: urlError || 'Missing required fields' });
  }

  const groups = normalizeStringArray(allowed_groups && allowed_groups.length ? allowed_groups : ['Domain Admins']);
  if (!groups.length) return res.status(400).json({ error: 'At least one allowed group is required' });

  const lookupDn = (lookup_bind_dn || '').trim();
  if (lookupDn && !lookup_bind_password) {
    return res.status(400).json({ error: 'A password is required when a lookup account bind DN is set' });
  }
  const lookupPasswordEnc = lookupDn && lookup_bind_password ? cryptoHelper.encrypt(lookup_bind_password) : null;

  const alertCfg = buildDomainAlertConfig(alert_config, null);

  const now = new Date().toISOString();
  try {
    const info = db.prepare(`INSERT INTO domains
      (name, domain_suffix, ldap_urls, base_dn, netbios_name, lookup_bind_dn, lookup_bind_password_enc, allowed_groups, tls_reject_unauthorized,
       feature_unlock, feature_reset, feature_force_change, audit_enabled, alert_config, enabled, created_at, updated_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
      name, domain_suffix.toLowerCase(), JSON.stringify(urls), base_dn, netbios_name || null,
      lookupDn || null, lookupPasswordEnc, JSON.stringify(groups),
      tls_reject_unauthorized ? 1 : 0, feature_unlock ? 1 : 0, feature_reset ? 1 : 0,
      feature_force_change ? 1 : 0, audit_enabled ? 1 : 0, JSON.stringify(alertCfg), enabled ? 1 : 0, now, now
    );
    logger.info('domain_created', { requestId: req.id, admin: req.admin.username, domain: name, suffix: domain_suffix });
    const row = db.prepare('SELECT * FROM domains WHERE id = ?').get(info.lastInsertRowid);
    res.json(domainPublic(row));
  } catch (e) {
    const msg = String(e.message || '').includes('UNIQUE') ? 'That email domain suffix is already configured' : e.message;
    logger.warn('domain_create_failed', { requestId: req.id, admin: req.admin.username, ...logger.errInfo(e) });
    res.status(400).json({ error: msg });
  }
});

router.put('/domains/:id', (req, res) => {
  const existing = db.prepare('SELECT * FROM domains WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Not found' });

  const b = req.body || {};

  let urlsJson = existing.ldap_urls;
  if (b.ldap_urls !== undefined) {
    const urls = normalizeStringArray(b.ldap_urls);
    const urlError = validateUrls(urls);
    if (urlError) return res.status(400).json({ error: urlError });
    urlsJson = JSON.stringify(urls);
  }

  let groupsJson = existing.allowed_groups;
  if (b.allowed_groups !== undefined) {
    const groups = normalizeStringArray(b.allowed_groups);
    if (!groups.length) return res.status(400).json({ error: 'At least one allowed group is required' });
    groupsJson = JSON.stringify(groups);
  }

  let alertJson = existing.alert_config;
  if (b.alert_config !== undefined) {
    alertJson = JSON.stringify(buildDomainAlertConfig(b.alert_config, existing.alert_config));
  }

  const netbiosValue = b.netbios_name !== undefined ? (b.netbios_name || null) : existing.netbios_name;

  // Lookup account: an empty/omitted DN means "no lookup account" (clears
  // any stored password too). A non-empty DN needs a password - either a
  // newly typed one, or the existing encrypted one if the DN hasn't
  // changed (so re-saving the form without retyping the password doesn't
  // wipe it out).
  let lookupDnValue = existing.lookup_bind_dn;
  let lookupPasswordValue = existing.lookup_bind_password_enc;
  if (b.lookup_bind_dn !== undefined) {
    const newDn = (b.lookup_bind_dn || '').trim();
    if (!newDn) {
      lookupDnValue = null;
      lookupPasswordValue = null;
    } else if (b.lookup_bind_password) {
      lookupDnValue = newDn;
      lookupPasswordValue = cryptoHelper.encrypt(b.lookup_bind_password);
    } else if (newDn === existing.lookup_bind_dn && existing.lookup_bind_password_enc) {
      lookupDnValue = newDn; // unchanged, keep existing password
    } else {
      return res.status(400).json({ error: 'A password is required when setting or changing the lookup account bind DN' });
    }
  }

  const now = new Date().toISOString();

  try {
    db.prepare(`UPDATE domains SET
        name=?, domain_suffix=?, ldap_urls=?, base_dn=?, netbios_name=?, lookup_bind_dn=?, lookup_bind_password_enc=?, allowed_groups=?,
        tls_reject_unauthorized=?, feature_unlock=?, feature_reset=?, feature_force_change=?,
        audit_enabled=?, alert_config=?, enabled=?, updated_at=?
      WHERE id=?`).run(
      b.name ?? existing.name,
      (b.domain_suffix ?? existing.domain_suffix).toLowerCase(),
      urlsJson,
      b.base_dn ?? existing.base_dn,
      netbiosValue,
      lookupDnValue,
      lookupPasswordValue,
      groupsJson,
      b.tls_reject_unauthorized !== undefined ? (b.tls_reject_unauthorized ? 1 : 0) : existing.tls_reject_unauthorized,
      b.feature_unlock !== undefined ? (b.feature_unlock ? 1 : 0) : existing.feature_unlock,
      b.feature_reset !== undefined ? (b.feature_reset ? 1 : 0) : existing.feature_reset,
      b.feature_force_change !== undefined ? (b.feature_force_change ? 1 : 0) : existing.feature_force_change,
      b.audit_enabled !== undefined ? (b.audit_enabled ? 1 : 0) : existing.audit_enabled,
      alertJson,
      b.enabled !== undefined ? (b.enabled ? 1 : 0) : existing.enabled,
      now,
      req.params.id
    );
    logger.info('domain_updated', { requestId: req.id, admin: req.admin.username, domainId: req.params.id });
    const row = db.prepare('SELECT * FROM domains WHERE id = ?').get(req.params.id);
    res.json(domainPublic(row));
  } catch (e) {
    const msg = String(e.message || '').includes('UNIQUE') ? 'That email domain suffix is already configured' : e.message;
    logger.warn('domain_update_failed', { requestId: req.id, admin: req.admin.username, domainId: req.params.id, ...logger.errInfo(e) });
    res.status(400).json({ error: msg });
  }
});

router.delete('/domains/:id', (req, res) => {
  db.prepare('DELETE FROM domains WHERE id = ?').run(req.params.id);
  logger.info('domain_deleted', { requestId: req.id, admin: req.admin.username, domainId: req.params.id });
  res.json({ ok: true });
});

// Credential-free connectivity test. Works for both an in-progress form
// (pass ldap_urls directly) and an already-saved domain (pass domainId).
router.post('/test-connection', async (req, res) => {
  let { ldap_urls, tls_reject_unauthorized, domainId } = req.body || {};
  if (domainId) {
    const domain = domainsModule.getById(domainId);
    if (!domain) return res.status(404).json({ error: 'Domain not found' });
    ldap_urls = domain.ldap_urls;
    tls_reject_unauthorized = domain.tls_reject_unauthorized;
  } else {
    ldap_urls = normalizeStringArray(ldap_urls);
  }
  const urlError = validateUrls(ldap_urls);
  if (urlError) return res.status(400).json({ error: urlError });
  const results = await ldap.testServers(ldap_urls, tls_reject_unauthorized);
  logger.info('connection_test', { requestId: req.id, admin: req.admin.username, results });
  res.json({ results });
});

// Tests the optional mail-attribute lookup account: binds with the given
// (or saved) credentials and, if a test email is supplied, searches for a
// matching user by their `mail` attribute. Works both for an unsaved
// in-progress form and an already-saved domain.
router.post('/test-lookup', async (req, res) => {
  const b = req.body || {};
  let domainConfig;

  if (b.domainId) {
    const domain = domainsModule.getById(b.domainId);
    if (!domain) return res.status(404).json({ error: 'Domain not found' });
    domainConfig = {
      ldap_urls: domain.ldap_urls,
      base_dn: domain.base_dn,
      tls_reject_unauthorized: domain.tls_reject_unauthorized,
      lookup_bind_dn: b.lookup_bind_dn || domain.lookup_bind_dn,
      lookup_bind_password_enc: b.lookup_bind_password
        ? cryptoHelper.encrypt(b.lookup_bind_password)
        : domain.lookup_bind_password_enc,
    };
  } else {
    const urls = normalizeStringArray(b.ldap_urls);
    const urlError = validateUrls(urls);
    if (urlError) return res.status(400).json({ error: urlError });
    if (!b.base_dn) return res.status(400).json({ error: 'Base DN is required' });
    if (!b.lookup_bind_dn || !b.lookup_bind_password) {
      return res.status(400).json({ error: 'Lookup bind DN and password are required to test' });
    }
    domainConfig = {
      ldap_urls: urls,
      base_dn: b.base_dn,
      tls_reject_unauthorized: b.tls_reject_unauthorized !== false,
      lookup_bind_dn: b.lookup_bind_dn,
      lookup_bind_password_enc: cryptoHelper.encrypt(b.lookup_bind_password),
    };
  }

  if (!domainConfig.lookup_bind_dn || !domainConfig.lookup_bind_password_enc) {
    return res.status(400).json({ error: 'Lookup bind DN and password are required to test' });
  }

  try {
    const testEmail = (b.testEmail || '').trim();
    if (testEmail) {
      const found = await ldap.lookupByMail(domainConfig, testEmail);
      const message = found
        ? `Bind succeeded. Found a matching account: ${found.userPrincipalName || found.sAMAccountName || found.dn}`
        : 'Bind succeeded, but no account was found with that email address.';
      logger.info('lookup_test', { requestId: req.id, admin: req.admin.username, found: !!found });
      res.json({ ok: true, message });
    } else {
      await ldap.lookupByMail(domainConfig, '__connection_test_no_such_address__@example.invalid');
      logger.info('lookup_test', { requestId: req.id, admin: req.admin.username, found: false });
      res.json({ ok: true, message: 'Bind succeeded.' });
    }
  } catch (e) {
    logger.warn('lookup_test_failed', { requestId: req.id, admin: req.admin.username, ...logger.errInfo(e) });
    res.status(400).json({ ok: false, error: e.message });
  }
});

// ---------- Global settings (audit) ----------

router.get('/settings', (req, res) => {
  const row = db.prepare("SELECT value FROM settings WHERE key = 'audit_logging_enabled'").get();
  res.json({ auditLoggingEnabled: !row || row.value === '1' });
});

router.put('/settings', (req, res) => {
  const { auditLoggingEnabled } = req.body || {};
  db.prepare(`INSERT INTO settings (key, value) VALUES ('audit_logging_enabled', ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value`).run(auditLoggingEnabled ? '1' : '0');
  logger.info('settings_updated', { requestId: req.id, admin: req.admin.username, auditLoggingEnabled: !!auditLoggingEnabled });
  res.json({ ok: true });
});

// ---------- Global email alert settings ----------

router.get('/alerts', (req, res) => {
  const cfg = mailer.getGlobalConfig();
  res.json({ ...cfg, smtp: mailer.sanitizeSmtp(cfg.smtp) });
});

router.put('/alerts', (req, res) => {
  const b = req.body || {};
  const existing = mailer.getGlobalConfig();
  const providedPassword = b.smtp && b.smtp.password;
  const passwordEnc = providedPassword ? cryptoHelper.encrypt(providedPassword) : existing.smtp.passwordEnc;
  const newCfg = {
    enabled: !!b.enabled,
    onLoginFailure: b.onLoginFailure !== undefined ? !!b.onLoginFailure : existing.onLoginFailure,
    onAccountAction: b.onAccountAction !== undefined ? !!b.onAccountAction : existing.onAccountAction,
    recipients: b.recipients !== undefined ? normalizeStringArray(b.recipients) : existing.recipients,
    smtp: {
      host: (b.smtp && b.smtp.host) ?? existing.smtp.host,
      port: (b.smtp && b.smtp.port) ?? existing.smtp.port,
      secure: b.smtp && b.smtp.secure !== undefined ? !!b.smtp.secure : existing.smtp.secure,
      tlsRejectUnauthorized: b.smtp && b.smtp.tlsRejectUnauthorized !== undefined ? !!b.smtp.tlsRejectUnauthorized : existing.smtp.tlsRejectUnauthorized,
      username: (b.smtp && b.smtp.username) ?? existing.smtp.username,
      from: (b.smtp && b.smtp.from) ?? existing.smtp.from,
      passwordEnc,
    },
  };
  mailer.setGlobalConfig(newCfg);
  logger.info('global_alert_settings_updated', { requestId: req.id, admin: req.admin.username, enabled: newCfg.enabled });
  res.json({ ...newCfg, smtp: mailer.sanitizeSmtp(newCfg.smtp) });
});

router.post('/alerts/test', async (req, res) => {
  const { domainId, smtp, recipients } = req.body || {};
  try {
    let domainRow = null;
    if (domainId) {
      domainRow = db.prepare('SELECT * FROM domains WHERE id = ?').get(domainId);
      if (!domainRow) return res.status(404).json({ error: 'Domain not found' });
    }

    let overrideSmtp;
    if (smtp && smtp.host) {
      overrideSmtp = { ...smtp };
      if (smtp.password) {
        overrideSmtp.passwordEnc = cryptoHelper.encrypt(smtp.password);
      } else {
        // No new password typed while testing - reuse whatever is already stored.
        const cfg = domainRow ? mailer.getDomainConfig(domainRow) : mailer.getGlobalConfig();
        overrideSmtp.passwordEnc = cfg.smtp.passwordEnc;
      }
    }
    const overrideRecipients = Array.isArray(recipients) ? normalizeStringArray(recipients) : undefined;

    const result = await mailer.sendTestEmail({ domainRow, overrideSmtp, overrideRecipients });
    logger.info('test_email_sent', { requestId: req.id, admin: req.admin.username, recipients: result.recipients.join(',') });
    res.json({ ok: true, recipients: result.recipients });
  } catch (e) {
    logger.warn('test_email_failed', { requestId: req.id, admin: req.admin.username, ...logger.errInfo(e) });
    res.status(400).json({ error: e.message });
  }
});

// ---------- Audit log ----------

function buildAuditQuery(query) {
  const { domainId, eventType, success } = query;
  let sql = 'SELECT * FROM audit_log WHERE 1=1';
  const params = [];
  if (domainId === 'unmatched') {
    sql += ' AND domain_id IS NULL';
  } else if (domainId) {
    sql += ' AND domain_id = ?';
    params.push(domainId);
  }
  if (eventType) {
    sql += ' AND event_type = ?';
    params.push(eventType);
  }
  if (success === '1' || success === '0') {
    sql += ' AND success = ?';
    params.push(Number(success));
  }
  return { sql, params };
}

router.get('/audit', (req, res) => {
  const { sql, params } = buildAuditQuery(req.query);
  const limit = Math.min(parseInt(req.query.limit, 10) || 200, 1000);
  const rows = db.prepare(`${sql} ORDER BY created_at DESC LIMIT ?`).all(...params, limit);
  res.json(rows);
});

function csvEscape(val) {
  const s = String(val === null || val === undefined ? '' : val);
  if (/[",\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

router.get('/audit/export', (req, res) => {
  const { sql, params } = buildAuditQuery(req.query);
  const rows = db.prepare(`${sql} ORDER BY created_at DESC`).all(...params);

  let filenamePart = 'all-domains';
  if (req.query.domainId === 'unmatched') {
    filenamePart = 'unmatched-domain';
  } else if (req.query.domainId) {
    const d = db.prepare('SELECT domain_suffix FROM domains WHERE id = ?').get(req.query.domainId);
    filenamePart = d ? d.domain_suffix : `domain-${req.query.domainId}`;
  }

  const header = ['Timestamp', 'Domain', 'Event', 'Actor', 'Target', 'Result', 'IP Address', 'Detail'];
  const lines = [header.map(csvEscape).join(',')];
  for (const r of rows) {
    lines.push([
      r.created_at,
      r.domain_label || '',
      r.event_type,
      r.actor_username || '',
      r.target_identifier || '',
      r.success ? 'Success' : 'Failure',
      r.ip_address || '',
      r.detail || '',
    ].map(csvEscape).join(','));
  }

  logger.info('audit_export', { requestId: req.id, admin: req.admin.username, rowCount: rows.length, filter: req.query });
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="audit-${filenamePart}-${new Date().toISOString().slice(0, 10)}.csv"`);
  res.send(lines.join('\n'));
});

// ---------- Local admin users ----------

router.get('/admins', (req, res) => {
  const rows = db.prepare('SELECT id, username, created_at FROM admin_users ORDER BY username').all();
  res.json(rows);
});

router.post('/admins', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password || password.length < 8) {
    return res.status(400).json({ error: 'Username and a password of at least 8 characters are required' });
  }
  try {
    const info = db.prepare('INSERT INTO admin_users (username, password_hash, created_at) VALUES (?,?,?)')
      .run(username, hashPassword(password), new Date().toISOString());
    logger.info('admin_user_created', { requestId: req.id, createdBy: req.admin.username, newAdmin: username });
    res.json({ id: info.lastInsertRowid, username });
  } catch (e) {
    const msg = String(e.message || '').includes('UNIQUE') ? 'Username already exists' : e.message;
    logger.warn('admin_user_create_failed', { requestId: req.id, createdBy: req.admin.username, ...logger.errInfo(e) });
    res.status(400).json({ error: msg });
  }
});

router.put('/admins/:id/password', (req, res) => {
  const { password } = req.body || {};
  if (!password || password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }
  db.prepare('UPDATE admin_users SET password_hash = ? WHERE id = ?').run(hashPassword(password), req.params.id);
  logger.info('admin_password_changed', { requestId: req.id, changedBy: req.admin.username, targetAdminId: req.params.id });
  res.json({ ok: true });
});

router.delete('/admins/:id', (req, res) => {
  const count = db.prepare('SELECT COUNT(*) c FROM admin_users').get().c;
  if (count <= 1) return res.status(400).json({ error: 'Cannot delete the last remaining admin user' });
  db.prepare('DELETE FROM admin_users WHERE id = ?').run(req.params.id);
  logger.info('admin_user_deleted', { requestId: req.id, deletedBy: req.admin.username, targetAdminId: req.params.id });
  res.json({ ok: true });
});

// ---------- Reports ----------
// Each report is a single SQL builder reused for both the on-screen JSON
// view (capped with LIMIT) and the CSV export (uncapped, up to a sane
// ceiling). Column aliases double as the table headers on the frontend.

function reportFilters(query) {
  const clauses = [];
  const params = [];
  if (query.domainId === 'unmatched') {
    clauses.push('domain_id IS NULL');
  } else if (query.domainId) {
    clauses.push('domain_id = ?');
    params.push(query.domainId);
  }
  if (query.from) { clauses.push('created_at >= ?'); params.push(query.from); }
  if (query.to) { clauses.push('created_at <= ?'); params.push(query.to); }
  return { where: clauses.length ? 'AND ' + clauses.join(' AND ') : '', params };
}

function reportLimit(query, def = 200) {
  return Math.min(parseInt(query.limit, 10) || def, 2000);
}

const REPORT_BUILDERS = {
  'failed-logins': (query) => {
    const { where, params } = reportFilters(query);
    return {
      sql: `SELECT domain_label AS "Domain", ip_address AS "Source IP", actor_username AS "Username entered",
              COUNT(*) AS "Attempts", MAX(created_at) AS "Last attempt", MAX(detail) AS "Last reason"
            FROM audit_log
            WHERE event_type = 'login' AND success = 0 ${where}
            GROUP BY domain_label, ip_address, actor_username
            ORDER BY "Attempts" DESC, "Last attempt" DESC`,
      params,
    };
  },
  'successful-events': (query) => {
    const { where, params } = reportFilters(query);
    let extra = '';
    const p = [...params];
    if (query.eventType) { extra = 'AND event_type = ?'; p.push(query.eventType); }
    return {
      sql: `SELECT domain_label AS "Domain", event_type AS "Event type", actor_username AS "Performed by",
              COUNT(*) AS "Occurrences", MAX(created_at) AS "Last occurrence"
            FROM audit_log
            WHERE success = 1 ${where} ${extra}
            GROUP BY domain_label, event_type, actor_username
            ORDER BY "Last occurrence" DESC`,
      params: p,
    };
  },
  'unsuccessful-actions': (query) => {
    const { where, params } = reportFilters(query);
    let extra = "AND event_type IN ('unlock','reset_password')";
    const p = [...params];
    if (query.eventType) { extra = 'AND event_type = ?'; p.push(query.eventType); }
    return {
      sql: `SELECT domain_label AS "Domain", event_type AS "Event type", actor_username AS "Performed by",
              target_identifier AS "Target account", COUNT(*) AS "Occurrences",
              MAX(created_at) AS "Last occurrence", MAX(detail) AS "Last reason"
            FROM audit_log
            WHERE success = 0 ${where} ${extra}
            GROUP BY domain_label, event_type, actor_username, target_identifier
            ORDER BY "Last occurrence" DESC`,
      params: p,
    };
  },
  'by-user': (query) => {
    const { where, params } = reportFilters(query);
    return {
      sql: `SELECT actor_username AS "User",
              COUNT(*) AS "Total events",
              SUM(CASE WHEN event_type='login' AND success=0 THEN 1 ELSE 0 END) AS "Failed logins",
              SUM(CASE WHEN event_type='login' AND success=1 THEN 1 ELSE 0 END) AS "Successful logins",
              SUM(CASE WHEN event_type='unlock' THEN 1 ELSE 0 END) AS "Unlocks performed",
              SUM(CASE WHEN event_type='reset_password' THEN 1 ELSE 0 END) AS "Resets performed",
              MAX(created_at) AS "Last activity"
            FROM audit_log
            WHERE 1=1 ${where}
            GROUP BY actor_username
            ORDER BY "Total events" DESC`,
      params,
    };
  },
  'by-target': (query) => {
    const { where, params } = reportFilters(query);
    return {
      sql: `SELECT domain_label AS "Domain", target_identifier AS "Target account",
              SUM(CASE WHEN event_type='unlock' THEN 1 ELSE 0 END) AS "Times unlocked",
              SUM(CASE WHEN event_type='reset_password' THEN 1 ELSE 0 END) AS "Times password reset",
              COUNT(*) AS "Total actions", MAX(created_at) AS "Last action"
            FROM audit_log
            WHERE target_identifier IS NOT NULL AND event_type IN ('unlock','reset_password') ${where}
            GROUP BY domain_label, target_identifier
            ORDER BY "Total actions" DESC`,
      params,
    };
  },
  'activity-trend': (query) => {
    const days = Math.min(parseInt(query.days, 10) || 30, 180);
    const since = new Date(Date.now() - days * 86400000).toISOString();
    const { where, params } = reportFilters({ ...query, from: query.from || since });
    return {
      sql: `SELECT substr(created_at, 1, 10) AS "Day",
              SUM(CASE WHEN event_type='login' AND success=1 THEN 1 ELSE 0 END) AS "Successful logins",
              SUM(CASE WHEN event_type='login' AND success=0 THEN 1 ELSE 0 END) AS "Failed logins",
              SUM(CASE WHEN event_type='unlock' THEN 1 ELSE 0 END) AS "Unlocks",
              SUM(CASE WHEN event_type='reset_password' THEN 1 ELSE 0 END) AS "Resets"
            FROM audit_log
            WHERE 1=1 ${where}
            GROUP BY "Day"
            ORDER BY "Day" DESC`,
      params,
    };
  },
};

router.get('/reports/summary', (req, res) => {
  const days = Math.min(parseInt(req.query.days, 10) || 30, 180);
  const since = new Date(Date.now() - days * 86400000).toISOString();
  const { where, params } = reportFilters({ ...req.query, from: req.query.from || since });
  const row = db.prepare(`
    SELECT
      SUM(CASE WHEN event_type='login' AND success=1 THEN 1 ELSE 0 END) AS logins_success,
      SUM(CASE WHEN event_type='login' AND success=0 THEN 1 ELSE 0 END) AS logins_failed,
      SUM(CASE WHEN event_type='unlock' THEN 1 ELSE 0 END) AS unlocks,
      SUM(CASE WHEN event_type='reset_password' THEN 1 ELSE 0 END) AS resets,
      COUNT(DISTINCT actor_username) AS active_users,
      COUNT(DISTINCT ip_address) AS distinct_ips
    FROM audit_log WHERE 1=1 ${where}
  `).get(...params);
  res.json({
    days,
    logins_success: row.logins_success || 0,
    logins_failed: row.logins_failed || 0,
    unlocks: row.unlocks || 0,
    resets: row.resets || 0,
    active_users: row.active_users || 0,
    distinct_ips: row.distinct_ips || 0,
  });
});

router.get('/reports/:key', (req, res) => {
  const builder = REPORT_BUILDERS[req.params.key];
  if (!builder) return res.status(404).json({ error: 'Unknown report' });
  const { sql, params } = builder(req.query);
  const limit = reportLimit(req.query);
  const rows = db.prepare(`${sql} LIMIT ?`).all(...params, limit);
  res.json(rows);
});

router.get('/reports/:key/export', (req, res) => {
  const builder = REPORT_BUILDERS[req.params.key];
  if (!builder) return res.status(404).json({ error: 'Unknown report' });
  const { sql, params } = builder(req.query);
  const rows = db.prepare(`${sql} LIMIT ?`).all(...params, 5000);
  const headers = rows.length ? Object.keys(rows[0]) : [];
  const lines = [headers.map(csvEscape).join(',')];
  rows.forEach((r) => lines.push(headers.map((h) => csvEscape(r[h])).join(',')));
  logger.info('report_export', { requestId: req.id, admin: req.admin.username, report: req.params.key, rowCount: rows.length });
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="report-${req.params.key}-${new Date().toISOString().slice(0, 10)}.csv"`);
  res.send(lines.length > 1 ? lines.join('\n') : 'No data for the selected filters\n');
});

// ---------- Email templates ----------

router.get('/templates-dir', (req, res) => {
  res.json({ dir: templates.TEMPLATES_DIR });
});

router.get('/templates', (req, res) => {
  res.json(templates.listTemplates());
});

const SAMPLE_VARS = {
  login_failure: { username: 'jdoe@contoso.com', domain: 'Contoso', reason: 'Invalid credentials', ip: '203.0.113.7', time: new Date().toISOString() },
  account_action: { action: 'Account unlock', result: 'Success', target: 'jdoe', actor: 'helpdesk1@contoso.com', domain: 'Contoso', detail: '', ip: '203.0.113.7', time: new Date().toISOString() },
};

router.post('/templates/:key/preview', (req, res) => {
  const { key } = req.params;
  if (!templates.DEFAULT_TEMPLATES[key]) return res.status(404).json({ error: 'Unknown template' });
  const { subject, body } = req.body || {};
  const vars = SAMPLE_VARS[key] || {};
  try {
    res.json({
      subject: templates.render(subject, vars),
      body: templates.render(body, vars),
    });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

router.put('/templates/:key', (req, res) => {
  const { key } = req.params;
  if (!templates.DEFAULT_TEMPLATES[key]) return res.status(404).json({ error: 'Unknown template' });
  const { subject, body } = req.body || {};
  if (!subject || !body) return res.status(400).json({ error: 'Subject and body are both required' });
  templates.setDbOverride(key, { subject, body });
  logger.info('template_updated', { requestId: req.id, admin: req.admin.username, key });
  res.json(templates.getTemplate(key));
});

router.delete('/templates/:key', (req, res) => {
  const { key } = req.params;
  if (!templates.DEFAULT_TEMPLATES[key]) return res.status(404).json({ error: 'Unknown template' });
  templates.clearDbOverride(key);
  logger.info('template_reset', { requestId: req.id, admin: req.admin.username, key });
  res.json(templates.getTemplate(key));
});

module.exports = router;
