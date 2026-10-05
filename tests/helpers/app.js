'use strict';
/**
 * Boots the REAL server.js as a child process (two listeners: user + admin
 * portal) against a throw-away data directory, with the fake AD / Duo SDKs
 * preloaded, and gives tests ready-made HTTP clients.
 */
const { spawn } = require('child_process');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { Client } = require('./client');
const { buildDirectory } = require('./directory');
const { TEST_JWT_SECRET, TEST_ENCRYPTION_KEY } = require('./env');

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const PRELOAD = path.join(__dirname, 'fakeServices.preload.js');
const ADMIN_USER = 'admin';
const ADMIN_PASSWORD = 'Adm1n-Test-Pass!';

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => { const { port } = srv.address(); srv.close(() => resolve(port)); });
  });
}

async function waitHealthy(url, child, getOutput, timeoutMs = 20000) {
  const started = Date.now();
  for (;;) {
    if (child.exitCode !== null || child.signalCode !== null) throw new Error(`server exited early (code ${child.exitCode} signal ${child.signalCode}):\n${getOutput()}`);
    try {
      const r = await fetch(`${url}/api/health`);
      if (r.status === 200) return;
    } catch (e) { /* not up yet */ }
    if (Date.now() - started > timeoutMs) throw new Error(`server did not become healthy at ${url}:\n${getOutput()}`);
    await new Promise((r) => setTimeout(r, 100));
  }
}

/**
 * opts.env        extra environment variables
 * opts.workDir    reuse a work dir (restart tests); data lives in <workDir>/data
 * opts.directory  object overriding the fake AD fixture (default buildDirectory())
 * opts.duo        true -> fake the Duo SDK
 */
async function startApp(opts = {}) {
  const workDir = opts.workDir || fs.mkdtempSync(path.join(os.tmpdir(), 'iam-it-'));
  const dataDir = path.join(workDir, 'data');
  const fixture = path.join(workDir, 'directory.json');
  const ldapLog = path.join(workDir, 'ldap.log');
  if (!fs.existsSync(fixture)) fs.writeFileSync(fixture, JSON.stringify(opts.directory || buildDirectory()));
  if (!fs.existsSync(ldapLog)) fs.writeFileSync(ldapLog, '');

  const [userPort, adminPort] = [await freePort(), await freePort()];
  const env = {
    ...process.env,
    NODE_ENV: 'test',
    DATA_DIR: dataDir,
    TEMPLATES_DIR: path.join(dataDir, 'templates'),
    PORT: String(userPort),
    ADMIN_PORT: String(adminPort),
    JWT_SECRET: TEST_JWT_SECRET,
    ENCRYPTION_KEY: TEST_ENCRYPTION_KEY,
    ADMIN_BOOTSTRAP_USER: ADMIN_USER,
    ADMIN_BOOTSTRAP_PASSWORD: ADMIN_PASSWORD,
    COOKIE_SECURE: 'false',
    AUTH_RATE_LIMIT_MAX: '1000',
    TRUST_PROXY: '',
    LOG_LEVEL: 'debug',
    FAKE_LDAP_FIXTURE: fixture,
    FAKE_LDAP_LOG: ldapLog,
    ...(opts.duo ? { FAKE_DUO: '1' } : {}),
    ...(opts.env || {}),
  };

  let output = '';
  const child = spawn(process.execPath, ['-r', PRELOAD, 'server.js'], { cwd: REPO_ROOT, env, stdio: ['ignore', 'pipe', 'pipe'] });
  child.stdout.on('data', (d) => { output += d; });
  child.stderr.on('data', (d) => { output += d; });

  const userUrl = `http://127.0.0.1:${userPort}`;
  const adminUrl = `http://127.0.0.1:${adminPort}`;
  await waitHealthy(userUrl, child, () => output);
  await waitHealthy(adminUrl, child, () => output);

  const app = {
    userUrl, adminUrl, userPort, adminPort, workDir, dataDir, env,
    output: () => output,
    ldapLog: () => fs.readFileSync(ldapLog, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)),
    newUserClient: () => new Client(userUrl),
    newAdminClient: () => new Client(adminUrl),
    async adminSession(username = ADMIN_USER, password = ADMIN_PASSWORD) {
      const c = new Client(adminUrl);
      const r = await c.post('/api/admin/login', { username, password });
      if (r.status !== 200) throw new Error(`admin login failed: ${r.status} ${r.text}`);
      return c;
    },
    async userSession(username, password) {
      const c = new Client(userUrl);
      const r = await c.post('/api/auth/login', { username, password });
      if (r.status !== 200) throw new Error(`user login failed: ${r.status} ${r.text}`);
      return c;
    },
    async stop({ keepFiles = false } = {}) {
      // NB: a child killed by a signal still has exitCode === null, so check signalCode too,
      // otherwise a second stop() would wait forever for an 'exit' event that already fired.
      const alive = child.exitCode === null && child.signalCode === null;
      if (alive) {
        child.kill('SIGTERM');
        await new Promise((resolve) => {
          const t = setTimeout(() => { child.kill('SIGKILL'); }, 3000);
          child.once('exit', () => { clearTimeout(t); resolve(); });
        });
      }
      if (!keepFiles) { try { fs.rmSync(workDir, { recursive: true, force: true }); } catch (e) { /* best effort */ } }
    },
  };
  return app;
}

module.exports = { startApp, ADMIN_USER, ADMIN_PASSWORD, REPO_ROOT };
