// Structured logging to stdout/stderr - this is what `docker compose logs`
// or `docker logs <container>` show. Kept dependency-free on purpose.

const LEVELS = { error: 0, warn: 1, info: 2, debug: 3 };

function currentLevel() {
  const raw = (process.env.LOG_LEVEL || 'info').toLowerCase();
  if (raw === 'silent') return -1;
  return Object.prototype.hasOwnProperty.call(LEVELS, raw) ? LEVELS[raw] : LEVELS.info;
}

function formatMeta(meta) {
  if (!meta || Object.keys(meta).length === 0) return '';
  const parts = [];
  for (const [key, value] of Object.entries(meta)) {
    if (value === undefined || value === null || value === '') continue;
    if (key === 'stack') continue; // printed separately, on its own lines
    const str = typeof value === 'string' ? value : JSON.stringify(value);
    // Quote values containing whitespace so log lines stay grep/awk friendly.
    parts.push(/\s/.test(str) ? `${key}="${str}"` : `${key}=${str}`);
  }
  return parts.join(' ');
}

function write(level, message, meta) {
  if (LEVELS[level] > currentLevel()) return;
  const time = new Date().toISOString();
  const metaStr = formatMeta(meta);
  const line = `${time} [${level.toUpperCase()}] ${message}${metaStr ? ' ' + metaStr : ''}`;
  const out = level === 'error' || level === 'warn' ? console.error : console.log;
  out(line);
  if (meta && meta.stack) {
    out(meta.stack.split('\n').map((l) => '    ' + l).join('\n'));
  }
}

// Pulls the useful bits off an Error (message, stack, code) into a plain
// object, since JSON.stringify(err) normally yields {} - Error properties
// aren't enumerable by default.
function errInfo(err) {
  if (!err) return {};
  return {
    error: err.message || String(err),
    code: err.code,
    stack: err.stack,
  };
}

module.exports = {
  error: (message, meta) => write('error', message, meta),
  warn: (message, meta) => write('warn', message, meta),
  info: (message, meta) => write('info', message, meta),
  debug: (message, meta) => write('debug', message, meta),
  errInfo,
};
