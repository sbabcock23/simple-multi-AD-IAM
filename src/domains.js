const db = require('./db');

function parseRow(row) {
  if (!row) return row;
  let urls = [];
  try {
    const parsed = JSON.parse(row.ldap_urls || '[]');
    if (Array.isArray(parsed)) urls = parsed;
  } catch (e) {
    urls = [];
  }
  return { ...row, ldap_urls: urls };
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
