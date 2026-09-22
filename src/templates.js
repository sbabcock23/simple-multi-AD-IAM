const fs = require('fs');
const path = require('path');
const db = require('./db');
const logger = require('./logger');

// Filesystem templates live under DATA_DIR (the same persisted volume as
// the database) so they survive image rebuilds and can be edited directly
// on disk or via a bind-mount, without needing the admin GUI. Files are
// named "<key>.subject.txt" and "<key>.body.txt".
const TEMPLATES_DIR = process.env.TEMPLATES_DIR ||
  path.join(process.env.DATA_DIR || path.join(__dirname, '..', 'data'), 'templates');

try {
  if (!fs.existsSync(TEMPLATES_DIR)) fs.mkdirSync(TEMPLATES_DIR, { recursive: true });
} catch (e) {
  logger.warn('templates_dir_create_failed', { path: TEMPLATES_DIR, ...logger.errInfo(e) });
}

const DEFAULT_TEMPLATES = {
  login_failure: {
    label: 'Failed login attempt',
    placeholders: ['username', 'domain', 'reason', 'ip', 'time'],
    subject: '[IAM Self-Service] Failed login attempt: {{username}}',
    body:
      'A failed login attempt was made to the IAM Self-Service portal.\n\n' +
      'Username entered: {{username}}\n' +
      'Domain: {{domain}}\n' +
      'Reason: {{reason}}\n' +
      'Source IP: {{ip}}\n' +
      'Time: {{time}}\n',
  },
  account_action: {
    label: 'Account action (unlock / reset password)',
    placeholders: ['action', 'result', 'target', 'actor', 'domain', 'detail', 'ip', 'time'],
    subject: '[IAM Self-Service] {{action}} {{result}}: {{target}}',
    body:
      'An account action was performed via the IAM Self-Service portal.\n\n' +
      'Action: {{action}}\n' +
      'Result: {{result}}\n' +
      'Target account: {{target}}\n' +
      'Performed by: {{actor}}\n' +
      'Domain: {{domain}}\n' +
      'Detail: {{detail}}\n' +
      'Source IP: {{ip}}\n' +
      'Time: {{time}}\n',
  },
};

function settingsKey(key) {
  return `email_template:${key}`;
}

function readFileTemplatePart(key, part) {
  const filePath = path.join(TEMPLATES_DIR, `${key}.${part}.txt`);
  try {
    if (!fs.existsSync(filePath)) return null;
    return fs.readFileSync(filePath, 'utf8').replace(/\r\n/g, '\n').replace(/\n$/, '');
  } catch (e) {
    logger.warn('template_file_read_failed', { key, part, ...logger.errInfo(e) });
    return null;
  }
}

function getDbOverride(key) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(settingsKey(key));
  if (!row) return null;
  try {
    return JSON.parse(row.value);
  } catch (e) {
    return null;
  }
}

// Resolves the effective subject/body for a template key, in priority
// order: an explicit save from the admin GUI (stored in the database),
// then a file on disk under TEMPLATES_DIR, then the built-in default.
// Subject and body are resolved independently, so e.g. a file-based body
// override still works even if only the subject was customized via the GUI.
function getTemplate(key) {
  const def = DEFAULT_TEMPLATES[key];
  if (!def) throw new Error(`Unknown email template: ${key}`);

  const dbOverride = getDbOverride(key) || {};
  const fileSubject = readFileTemplatePart(key, 'subject');
  const fileBody = readFileTemplatePart(key, 'body');

  const subject = dbOverride.subject || fileSubject || def.subject;
  const body = dbOverride.body || fileBody || def.body;
  const source = dbOverride.subject || dbOverride.body ? 'database' : (fileSubject || fileBody ? 'file' : 'default');

  return {
    key,
    label: def.label,
    placeholders: def.placeholders,
    subject,
    body,
    source,
    defaultSubject: def.subject,
    defaultBody: def.body,
  };
}

function setDbOverride(key, { subject, body }) {
  if (!DEFAULT_TEMPLATES[key]) throw new Error(`Unknown email template: ${key}`);
  db.prepare(`INSERT INTO settings (key, value) VALUES (?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value`).run(settingsKey(key), JSON.stringify({ subject, body }));
}

function clearDbOverride(key) {
  db.prepare('DELETE FROM settings WHERE key = ?').run(settingsKey(key));
}

function render(str, vars) {
  return String(str || '').replace(/\{\{(\w+)\}\}/g, (match, name) =>
    Object.prototype.hasOwnProperty.call(vars, name) ? String(vars[name] === undefined || vars[name] === null ? '' : vars[name]) : match
  );
}

function renderTemplate(key, vars) {
  const tpl = getTemplate(key);
  return { subject: render(tpl.subject, vars), text: render(tpl.body, vars) };
}

function listTemplates() {
  return Object.keys(DEFAULT_TEMPLATES).map((key) => getTemplate(key));
}

module.exports = {
  DEFAULT_TEMPLATES,
  TEMPLATES_DIR,
  getTemplate,
  setDbOverride,
  clearDbOverride,
  render,
  renderTemplate,
  listTemplates,
};
