require('dotenv').config();
const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');

const logger = require('./src/logger');
const db = require('./src/db');
const { hashPassword } = require('./src/auth');
const { requireAdminAuth, requireUserAuth } = require('./src/middleware');

// These two handlers are a safety net, not a substitute for fixing bugs:
// if something throws outside of Express's normal request handling (e.g. an
// event emitter error with no listener, or a rejected promise nobody
// awaited), log it clearly instead of letting it disappear or silently take
// the process down without explanation.
process.on('uncaughtException', (err) => {
  logger.error('uncaught_exception', logger.errInfo(err));
  // The process may be in an inconsistent state after this; exit so Docker's
  // restart policy can bring up a clean instance, rather than limping on.
  process.exit(1);
});
process.on('unhandledRejection', (reason) => {
  const err = reason instanceof Error ? reason : new Error(String(reason));
  logger.error('unhandled_rejection', logger.errInfo(err));
});

const app = express();
app.disable('x-powered-by');

// If this app sits behind a reverse proxy / load balancer (nginx, Traefik,
// a PaaS router, etc.), it will receive an X-Forwarded-For header. Express
// needs to be told how many proxy hops to trust so it can resolve the real
// client IP - otherwise express-rate-limit throws a ValidationError on
// every request to a rate-limited route (ERR_ERL_UNEXPECTED_X_FORWARDED_FOR),
// which previously surfaced to users as a broken, non-JSON 500 response on
// both login forms. Set TRUST_PROXY to the number of proxy hops in front of
// this app (usually 1), or leave unset if the app is reachable directly.
const trustProxySetting = process.env.TRUST_PROXY;
if (trustProxySetting !== undefined && trustProxySetting !== '') {
  const asNumber = Number(trustProxySetting);
  app.set('trust proxy', Number.isNaN(asNumber) ? trustProxySetting : asNumber);
}

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(cookieParser());

// Request ID + access logging. Every response carries an X-Request-Id
// header, and every error response includes the same ID in its JSON body,
// so a report of "it failed" can be matched to the exact log lines for that
// request with `docker compose logs | grep <id>`.
app.use((req, res, next) => {
  req.id = crypto.randomBytes(6).toString('hex');
  res.setHeader('X-Request-Id', req.id);
  const start = Date.now();
  res.on('finish', () => {
    const level = res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info';
    logger[level]('request', {
      requestId: req.id,
      method: req.method,
      path: req.path,
      status: res.statusCode,
      durationMs: Date.now() - start,
      ip: req.ip,
    });
  });
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

// Bootstrap the first local admin account on first run only.
const adminCount = db.prepare('SELECT COUNT(*) c FROM admin_users').get().c;
if (adminCount === 0) {
  const user = process.env.ADMIN_BOOTSTRAP_USER || 'admin';
  const pass = process.env.ADMIN_BOOTSTRAP_PASSWORD || 'ChangeMe123!';
  db.prepare('INSERT INTO admin_users (username, password_hash, created_at) VALUES (?,?,?)')
    .run(user, hashPassword(pass), new Date().toISOString());
  logger.info('bootstrap_admin_created', { username: user });
  console.log(`[bootstrap] Created initial admin user '${user}'. CHANGE THIS PASSWORD IMMEDIATELY.`);
}

const authRateLimitMax = parseInt(process.env.AUTH_RATE_LIMIT_MAX, 10) || 100;
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: authRateLimitMax,
  standardHeaders: true,
  legacyHeaders: false,
  // Prevent a missing/incorrect TRUST_PROXY setting from throwing and
  // breaking login entirely (ERR_ERL_UNEXPECTED_X_FORWARDED_FOR). Rate
  // limiting still works; it just can't be fooled by this specific check.
  validate: { xForwardedForHeader: false },
});

app.use('/api/admin', authLimiter, require('./src/routes/adminAuth'));
app.use('/api/admin', requireAdminAuth, require('./src/routes/adminApi'));
app.use('/api/auth', authLimiter, require('./src/routes/userAuth'));
app.use('/api/users', requireUserAuth, require('./src/routes/userApi'));

app.get('/api/health', (req, res) => res.json({ ok: true }));

app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// Catch-all: anything that reaches here is a bug we didn't anticipate
// (every route above handles its own expected errors and responds with
// JSON directly). This guarantees the client NEVER receives Express's
// default HTML error page - which is what previously made unexpected
// failures show up in the browser as a generic, undiagnosable
// "Request failed" instead of a real error message.
app.use((err, req, res, next) => {
  logger.error('unhandled_route_error', {
    requestId: req.id, method: req.method, path: req.path, ...logger.errInfo(err),
  });
  if (res.headersSent) return next(err);
  res.status(500).json({
    error: 'Something went wrong on the server. Please try again or contact your administrator.',
    requestId: req.id,
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  logger.info('server_listening', { port: PORT, logLevel: process.env.LOG_LEVEL || 'info', authRateLimitMax });
  console.log(`IAM self-service app listening on port ${PORT}`);
});
