const db = require('./db');
const logger = require('./logger');

// How long audit records are kept, in days. 0 means "keep forever" (the
// behaviour before this setting existed), so upgrading never deletes anything
// until an administrator opts in.
const SETTINGS_KEY = 'audit_retention_days';
const MAX_DAYS = 3650; // 10 years
const PURGE_INTERVAL_MS = 60 * 60 * 1000; // hourly

function getDays() {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(SETTINGS_KEY);
  const n = row ? Number(row.value) : 0;
  return Number.isInteger(n) && n >= 0 && n <= MAX_DAYS ? n : 0;
}

function setDays(input) {
  const n = Number(input);
  if (!Number.isInteger(n) || n < 0 || n > MAX_DAYS) {
    throw Object.assign(
      new Error(`Audit retention must be a whole number of days between 0 (keep forever) and ${MAX_DAYS}`),
      { status: 400 }
    );
  }
  db.prepare(`INSERT INTO settings (key, value) VALUES (?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value`).run(SETTINGS_KEY, String(n));
  return n;
}

// Deletes audit records older than the retention period. created_at is stored
// as an ISO-8601 UTC string, so a plain string comparison is a time comparison.
function purge() {
  const days = getDays();
  if (!days) return { days, deleted: 0 };
  const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
  const result = db.prepare('DELETE FROM audit_log WHERE created_at < ?').run(cutoff);
  if (result.changes) logger.info('audit_records_purged', { days, deleted: result.changes, cutoff });
  return { days, deleted: result.changes };
}

function startScheduler() {
  const run = () => {
    try { purge(); } catch (e) { logger.error('audit_purge_failed', logger.errInfo(e)); }
  };
  run();
  const timer = setInterval(run, PURGE_INTERVAL_MS);
  if (timer.unref) timer.unref();
}

module.exports = { getDays, setDays, purge, startScheduler, MAX_DAYS };
