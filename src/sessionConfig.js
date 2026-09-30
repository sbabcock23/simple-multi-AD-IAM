const db = require('./db');

// Idle-session timeouts, in minutes, configured globally in the admin
// portal. The user portal and the admin portal are deliberately independent
// so an administrator can, for example, keep help-desk sessions short while
// leaving the admin console open longer (or the reverse).
const DEFAULTS = { userTimeoutMinutes: 120, adminTimeoutMinutes: 480 };
const MIN_MINUTES = 5;
const MAX_MINUTES = 1440; // 24 hours
const SETTINGS_KEY = 'session_config';

function clamp(value, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(MAX_MINUTES, Math.max(MIN_MINUTES, Math.round(n)));
}

function get() {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(SETTINGS_KEY);
  let parsed = {};
  try { parsed = row ? JSON.parse(row.value) : {}; } catch (e) { parsed = {}; }
  return {
    userTimeoutMinutes: clamp(parsed.userTimeoutMinutes, DEFAULTS.userTimeoutMinutes),
    adminTimeoutMinutes: clamp(parsed.adminTimeoutMinutes, DEFAULTS.adminTimeoutMinutes),
  };
}

// Throws a validation error (status 400) rather than silently clamping, so
// the admin sees exactly what was rejected.
function validate(input) {
  const out = {};
  for (const [field, label] of [['userTimeoutMinutes', 'User portal'], ['adminTimeoutMinutes', 'Admin portal']]) {
    const n = Number(input[field]);
    if (!Number.isInteger(n) || n < MIN_MINUTES || n > MAX_MINUTES) {
      throw Object.assign(
        new Error(`${label} session timeout must be a whole number of minutes between ${MIN_MINUTES} and ${MAX_MINUTES}`),
        { status: 400 }
      );
    }
    out[field] = n;
  }
  return out;
}

function set(input) {
  const cfg = validate(input || {});
  db.prepare(`INSERT INTO settings (key, value) VALUES (?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value`).run(SETTINGS_KEY, JSON.stringify(cfg));
  return cfg;
}

function userTimeoutSeconds() { return get().userTimeoutMinutes * 60; }
function adminTimeoutSeconds() { return get().adminTimeoutMinutes * 60; }

module.exports = { get, set, validate, userTimeoutSeconds, adminTimeoutSeconds, DEFAULTS, MIN_MINUTES, MAX_MINUTES };
