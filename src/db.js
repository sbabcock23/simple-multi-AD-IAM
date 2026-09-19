const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const logger = require('./logger');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  logger.info('data_dir_created', { path: DATA_DIR });
}

const dbPath = path.join(DATA_DIR, 'iam.db');
let db;
try {
  db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  logger.info('database_opened', { path: dbPath });
} catch (err) {
  logger.error('database_open_failed', { path: dbPath, ...logger.errInfo(err) });
  throw err;
}

try {
  db.exec(`
CREATE TABLE IF NOT EXISTS admin_users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS domains (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  domain_suffix TEXT UNIQUE NOT NULL,
  ldap_urls TEXT NOT NULL,        -- JSON array of connection strings, e.g. ["ldaps://dc1:636","ldaps://dc2:636"]
  base_dn TEXT NOT NULL,
  netbios_name TEXT,              -- optional, e.g. "CONTOSO" - enables DOMAIN\\sAMAccountName bind fallback
  lookup_bind_dn TEXT,             -- optional - resolves login by the AD "mail" attribute (see ensureColumn note below)
  lookup_bind_password_enc TEXT,
  allowed_groups TEXT NOT NULL DEFAULT '["Domain Admins"]', -- JSON array of AD group names permitted to sign in
  tls_reject_unauthorized INTEGER NOT NULL DEFAULT 1,
  feature_unlock INTEGER NOT NULL DEFAULT 1,
  feature_reset INTEGER NOT NULL DEFAULT 1,
  feature_force_change INTEGER NOT NULL DEFAULT 1,
  audit_enabled INTEGER NOT NULL DEFAULT 1,
  alert_config TEXT NOT NULL DEFAULT '{}', -- JSON: per-domain alert enable/trigger/recipient/SMTP-override settings
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL,
  domain_id INTEGER,             -- NULL when the login's domain suffix didn't match any configured domain
  domain_label TEXT,             -- denormalized domain name, kept even if the domain is later deleted
  event_type TEXT NOT NULL,      -- 'login' | 'logout' | 'search' | 'unlock' | 'reset_password'
  actor_username TEXT NOT NULL,  -- the signed-in end user who performed the action
  target_identifier TEXT,        -- the AD account/query acted upon, where applicable
  success INTEGER NOT NULL,
  detail TEXT,
  ip_address TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_domain ON audit_log(domain_id);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_username);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
`);
} catch (err) {
  logger.error('schema_init_failed', logger.errInfo(err));
  throw err;
}

// ---- Lightweight migration support for databases created by earlier
// versions of this app. ----

function columnExists(table, column) {
  return db.prepare(`PRAGMA table_info(${table})`).all().some((c) => c.name === column);
}

function ensureColumn(table, column, definition) {
  if (!columnExists(table, column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
    logger.info('migration_column_added', { table, column });
  }
}

try {
  ensureColumn('domains', 'ldap_urls', "TEXT NOT NULL DEFAULT '[]'");
  ensureColumn('domains', 'audit_enabled', 'INTEGER NOT NULL DEFAULT 1');
  ensureColumn('domains', 'netbios_name', 'TEXT');
  ensureColumn('domains', 'allowed_groups', "TEXT NOT NULL DEFAULT '[\"Domain Admins\"]'");
  ensureColumn('domains', 'alert_config', "TEXT NOT NULL DEFAULT '{}'");
  // Optional, narrowly-scoped account used ONLY to resolve "this email
  // address -> this AD account" before authentication, when login by the
  // real `mail` attribute is needed (as opposed to the UPN or a
  // sAMAccountName-matches-local-part assumption). Never used for search,
  // unlock, or password reset - those always run as the signed-in user.
  ensureColumn('domains', 'lookup_bind_dn', 'TEXT');
  ensureColumn('domains', 'lookup_bind_password_enc', 'TEXT');

  // If this is an upgrade from a version that had a single `ldap_url` column,
  // backfill ldap_urls from it so existing domains keep working.
  if (columnExists('domains', 'ldap_url')) {
    const rows = db.prepare("SELECT id, ldap_url FROM domains WHERE (ldap_urls IS NULL OR ldap_urls = '[]') AND ldap_url IS NOT NULL").all();
    const update = db.prepare('UPDATE domains SET ldap_urls = ? WHERE id = ?');
    for (const row of rows) {
      update.run(JSON.stringify([row.ldap_url]), row.id);
    }
    if (rows.length) logger.info('migration_ldap_urls_backfilled', { domainCount: rows.length });
    // Note: legacy bind_dn / bind_password_enc columns (if present) are no
    // longer read anywhere in the app and can be ignored; they are left in
    // place rather than dropped to avoid requiring a specific SQLite version.
  }
} catch (err) {
  logger.error('migration_failed', logger.errInfo(err));
  throw err;
}

// Seed default settings.
try {
  const auditSetting = db.prepare("SELECT 1 FROM settings WHERE key = 'audit_logging_enabled'").get();
  if (!auditSetting) {
    db.prepare("INSERT INTO settings (key, value) VALUES ('audit_logging_enabled', '1')").run();
    logger.info('default_settings_seeded', { key: 'audit_logging_enabled' });
  }
  const alertSetting = db.prepare("SELECT 1 FROM settings WHERE key = 'alert_config'").get();
  if (!alertSetting) {
    // Alerts default to OFF globally (unlike audit logging) since they
    // depend on SMTP being configured; nothing is sent until an admin
    // opts in and fills in a mail server.
    db.prepare("INSERT INTO settings (key, value) VALUES ('alert_config', '{}')").run();
    logger.info('default_settings_seeded', { key: 'alert_config' });
  }
} catch (err) {
  logger.error('settings_seed_failed', logger.errInfo(err));
  throw err;
}

module.exports = db;
