const db = require('./db');

function safeParseArray(json, fallback) {
  try {
    const parsed = JSON.parse(json || 'null');
    return Array.isArray(parsed) ? parsed : fallback;
  } catch (e) {
    return fallback;
  }
}

function safeParseObject(json) {
  try {
    const parsed = JSON.parse(json || '{}');
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch (e) {
    return {};
  }
}

function parseRow(row) {
  if (!row) return row;
  return {
    ...row,
    ldap_urls: safeParseArray(row.ldap_urls, []),
    allowed_groups: safeParseArray(row.allowed_groups, ['Domain Admins']),
    alert_config: safeParseObject(row.alert_config),
  };
}

function getById(id) {
  return parseRow(db.prepare('SELECT * FROM domains WHERE id = ?').get(id));
}

function getBySuffix(suffix) {
  return parseRow(db.prepare('SELECT * FROM domains WHERE domain_suffix = ? AND enabled = 1').get(suffix));
}

function listAll() {
  return db.prepare('SELECT * FROM domains ORDER BY name').all().map(parseRow);
}

module.exports = { getById, getBySuffix, listAll };
