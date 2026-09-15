const express = require('express');
const router = express.Router();
const db = require('../db');
const domainsModule = require('../domains');
const ldap = require('../ldap');
const logger = require('../logger');
const { hashPassword } = require('../auth');

function parseUrls(json) {
  try {
    const arr = JSON.parse(json || '[]');
    return Array.isArray(arr) ? arr : [];
  } catch (e) {
    return [];
  }
}

function domainPublic(row) {
  return {
    id: row.id,
    name: row.name,
    domain_suffix: row.domain_suffix,
    ldap_urls: parseUrls(row.ldap_urls),
    base_dn: row.base_dn,
    tls_reject_unauthorized: !!row.tls_reject_unauthorized,
    feature_unlock: !!row.feature_unlock,
    feature_reset: !!row.feature_reset,
    feature_force_change: !!row.feature_force_change,
    audit_enabled: !!row.audit_enabled,
    enabled: !!row.enabled,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

function normalizeUrls(input) {
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

// ---------- Domains ----------

router.get('/domains', (req, res) => {
  const rows = db.prepare('SELECT * FROM domains ORDER BY name').all();
  res.json(rows.map(domainPublic));
});

router.post('/domains', (req, res) => {
  const {
    name, domain_suffix, ldap_urls, base_dn,
    tls_reject_unauthorized = true, feature_unlock = true, feature_reset = true,
    feature_force_change = true, audit_enabled = true, enabled = true,
  } = req.body || {};

  const urls = normalizeUrls(ldap_urls);
  const urlError = validateUrls(urls);
  if (!name || !domain_suffix || !base_dn || urlError) {
    return res.status(400).json({ error: urlError || 'Missing required fields' });
  }

  const now = new Date().toISOString();
  try {
    const info = db.prepare(`INSERT INTO domains
      (name, domain_suffix, ldap_urls, base_dn, tls_reject_unauthorized,
       feature_unlock, feature_reset, feature_force_change, audit_enabled, enabled, created_at, updated_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`).run(
      name, domain_suffix.toLowerCase(), JSON.stringify(urls), base_dn,
      tls_reject_unauthorized ? 1 : 0, feature_unlock ? 1 : 0, feature_reset ? 1 : 0,
      feature_force_change ? 1 : 0, audit_enabled ? 1 : 0, enabled ? 1 : 0, now, now
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
    const urls = normalizeUrls(b.ldap_urls);
    const urlError = validateUrls(urls);
    if (urlError) return res.status(400).json({ error: urlError });
    urlsJson = JSON.stringify(urls);
  }
  const now = new Date().toISOString();

  try {
    db.prepare(`UPDATE domains SET
        name=?, domain_suffix=?, ldap_urls=?, base_dn=?,
        tls_reject_unauthorized=?, feature_unlock=?, feature_reset=?, feature_force_change=?,
        audit_enabled=?, enabled=?, updated_at=?
      WHERE id=?`).run(
      b.name ?? existing.name,
      (b.domain_suffix ?? existing.domain_suffix).toLowerCase(),
      urlsJson,
      b.base_dn ?? existing.base_dn,
      b.tls_reject_unauthorized !== undefined ? (b.tls_reject_unauthorized ? 1 : 0) : existing.tls_reject_unauthorized,
      b.feature_unlock !== undefined ? (b.feature_unlock ? 1 : 0) : existing.feature_unlock,
      b.feature_reset !== undefined ? (b.feature_reset ? 1 : 0) : existing.feature_reset,
      b.feature_force_change !== undefined ? (b.feature_force_change ? 1 : 0) : existing.feature_force_change,
      b.audit_enabled !== undefined ? (b.audit_enabled ? 1 : 0) : existing.audit_enabled,
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
    ldap_urls = normalizeUrls(ldap_urls);
  }
  const urlError = validateUrls(ldap_urls);
  if (urlError) return res.status(400).json({ error: urlError });
  const results = await ldap.testServers(ldap_urls, tls_reject_unauthorized);
  logger.info('connection_test', { requestId: req.id, admin: req.admin.username, results });
  res.json({ results });
});

// ---------- Global settings ----------

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

module.exports = router;
