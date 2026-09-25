require('dotenv').config();
const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');

const logger = require('./src/logger');
const db = require('./src/db');
const { hashPassword } = require('./src/auth');
const { requireAdminAuth, requireUserAuth } = require('./src/middleware');

process.on('uncaughtException', (err) => {
  logger.error('uncaught_exception', logger.errInfo(err));
  process.exit(1);
});
process.on('unhandledRejection', (reason) => {
  const err = reason instanceof Error ? reason : new Error(String(reason));
  logger.error('unhandled_rejection', logger.errInfo(err));
});

const PUBLIC_DIR = path.join(__dirname, 'public');

const trustProxySetting = process.env.TRUST_PROXY;
function applyTrustProxy(app) {
  if (trustProxySetting !== undefined && trustProxySetting !== '') {
    const asNumber = Number(trustProxySetting);
    app.set('trust proxy', Number.isNaN(asNumber) ? trustProxySetting : asNumber);
  }
}

const authRateLimitMax = parseInt(process.env.AUTH_RATE_LIMIT_MAX, 10) || 100;
function createAuthLimiter() {
  return rateLimit({
    windowMs: 15 * 60 * 1000,
    max: authRateLimitMax,
    standardHeaders: true,
    legacyHeaders: false,
    validate: { xForwardedForHeader: false },
  });
}

function sendStaticFile(res, filePath) {
  const ext = path.extname(filePath);
  const types = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css' };
  if (!fs.existsSync(filePath)) {
    res.statusCode = 404;
    res.end('Not found');
    return;
  }
  res.setHeader('Content-Type', types[ext] || 'application/octet-stream');
  res.sendFile(filePath);
}

function createBaseApp(name) {
  const app = express();
  app.disable('x-powered-by');
  applyTrustProxy(app);
  app.use(helmet());
  app.use(express.json());
  app.use(cookieParser());

  app.use((req, res, next) => {
    req.id = crypto.randomBytes(6).toString('hex');
    res.setHeader('X-Request-Id', req.id);
    const start = Date.now();
    res.on('finish', () => {
      const level = res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info';
      logger[level]('request', {
        app: name, requestId: req.id, method: req.method, path: req.path,
        status: res.statusCode, durationMs: Date.now() - start, ip: req.ip,
      });
    });
    next();
  });

  app.get('/api/health', (req, res) => res.json({ ok: true, app: name }));

  return app;
}

function attachErrorHandler(app) {
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
}

// Bootstrap the first local admin account on first run only.
const adminCount = db.prepare('SELECT COUNT(*) c FROM admin_users').get().c;
if (adminCount === 0) {
  const bootstrapUser = process.env.ADMIN_BOOTSTRAP_USER || 'admin';
  const bootstrapPass = process.env.ADMIN_BOOTSTRAP_PASSWORD || 'ChangeMe123!';
  db.prepare('INSERT INTO admin_users (username, password_hash, created_at) VALUES (?,?,?)')
    .run(bootstrapUser, hashPassword(bootstrapPass), new Date().toISOString());
  logger.info('bootstrap_admin_created', { username: bootstrapUser });
  console.log(`[bootstrap] Created initial admin user '${bootstrapUser}'. CHANGE THIS PASSWORD IMMEDIATELY.`);
}

// ---------------------------------------------------------------------
// User portal - its own server, its own port. Only user-facing routes and
// static assets are registered here; admin routes/pages do not exist on
// this app at all.
// ---------------------------------------------------------------------
const userApp = createBaseApp('user');
userApp.use('/api/auth', createAuthLimiter(), require('./src/routes/userAuth'));
userApp.use('/api/users', requireUserAuth, require('./src/routes/userApi'));
userApp.get('/css/style.css', (req, res) => sendStaticFile(res, path.join(PUBLIC_DIR, 'css', 'style.css')));
userApp.get('/js/app.js', (req, res) => sendStaticFile(res, path.join(PUBLIC_DIR, 'js', 'app.js')));
userApp.get('/', (req, res) => sendStaticFile(res, path.join(PUBLIC_DIR, 'index.html')));
attachErrorHandler(userApp);

// ---------------------------------------------------------------------
// Admin portal - a completely separate server on its own port. Only admin
// routes/static assets exist here; the user portal cannot be reached from
// this port, and vice versa.
// ---------------------------------------------------------------------
const adminApp = createBaseApp('admin');
adminApp.use('/api/admin', createAuthLimiter(), require('./src/routes/adminAuth'));
adminApp.use('/api/admin', requireAdminAuth, require('./src/routes/adminApi'));
adminApp.get('/css/style.css', (req, res) => sendStaticFile(res, path.join(PUBLIC_DIR, 'css', 'style.css')));
adminApp.get('/js/admin.js', (req, res) => sendStaticFile(res, path.join(PUBLIC_DIR, 'js', 'admin.js')));
adminApp.get('/', (req, res) => sendStaticFile(res, path.join(PUBLIC_DIR, 'admin.html')));
attachErrorHandler(adminApp);

const USER_PORT = process.env.PORT || 3000;
const ADMIN_PORT = process.env.ADMIN_PORT || 3001;

userApp.listen(USER_PORT, () => {
  logger.info('server_listening', { app: 'user', port: USER_PORT, logLevel: process.env.LOG_LEVEL || 'info', authRateLimitMax });
  console.log(`IAM user portal listening on port ${USER_PORT}`);
});

adminApp.listen(ADMIN_PORT, () => {
  logger.info('server_listening', { app: 'admin', port: ADMIN_PORT, logLevel: process.env.LOG_LEVEL || 'info', authRateLimitMax });
  console.log(`IAM admin portal listening on port ${ADMIN_PORT}`);
});
