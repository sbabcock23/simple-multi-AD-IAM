const db = require('./db');

const THEMES = ['light', 'dark'];

function key(portal, username) {
  return { portal, username: String(username || '').trim().toLowerCase() };
}

// Returns 'light' | 'dark', or null if this person has never chosen one
// (the browser then follows the operating system setting).
function getTheme(portal, username) {
  const k = key(portal, username);
  const row = db.prepare('SELECT theme FROM user_preferences WHERE portal = ? AND username = ?').get(k.portal, k.username);
  return row && THEMES.includes(row.theme) ? row.theme : null;
}

function setTheme(portal, username, theme) {
  if (!THEMES.includes(theme)) {
    throw Object.assign(new Error('Theme must be "light" or "dark"'), { status: 400 });
  }
  const k = key(portal, username);
  db.prepare(`INSERT INTO user_preferences (portal, username, theme, updated_at) VALUES (?, ?, ?, ?)
    ON CONFLICT(portal, username) DO UPDATE SET theme = excluded.theme, updated_at = excluded.updated_at`)
    .run(k.portal, k.username, theme, new Date().toISOString());
  return theme;
}

module.exports = { getTheme, setTheme, THEMES };
