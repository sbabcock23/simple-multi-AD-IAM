'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');

const TEST_JWT_SECRET = 'test-jwt-secret-0123456789abcdef0123456789abcdef';
const TEST_ENCRYPTION_KEY = 'test-encryption-key-0123456789abcdef0123456789';

/**
 * For IN-PROCESS unit tests: points the app at a throw-away data directory and
 * known secrets BEFORE any src/ module is required (src/db.js opens the
 * database at require time). node --test runs every file in its own process,
 * so this is isolated per test file. Returns { dataDir, cleanup }.
 */
function setupUnitEnv(extra = {}) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'iam-unit-'));
  Object.assign(process.env, {
    DATA_DIR: path.join(dataDir, 'data'),
    TEMPLATES_DIR: path.join(dataDir, 'templates'),
    JWT_SECRET: TEST_JWT_SECRET,
    ENCRYPTION_KEY: TEST_ENCRYPTION_KEY,
    COOKIE_SECURE: 'false',
    LOG_LEVEL: 'silent',
  }, extra);
  return {
    dataDir,
    cleanup() { try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch (e) { /* best effort */ } },
  };
}

module.exports = { setupUnitEnv, TEST_JWT_SECRET, TEST_ENCRYPTION_KEY };
