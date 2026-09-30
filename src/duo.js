const db = require('./db');
const logger = require('./logger');
const cryptoHelper = require('./crypto');

const GLOBAL_DEFAULTS = { mode: 'disabled', clientId: '', clientSecretEnc: '', apiHostname: '', redirectUrl: '' };
const DOMAIN_DEFAULTS = { mode: 'inherit', credentialsOverride: false, clientId: '', clientSecretEnc: '', apiHostname: '', redirectUrl: '' };

function mergeConfig(partial, defaults) {
  const p = partial && typeof partial === 'object' ? partial : {};
  return { ...defaults, ...p };
}

function getGlobalConfig() {
  const row = db.prepare("SELECT value FROM settings WHERE key = 'duo_config'").get();
  let parsed = {};
  try { parsed = row ? JSON.parse(row.value) : {}; } catch (e) { parsed = {}; }
  return mergeConfig(parsed, GLOBAL_DEFAULTS);
}

function setGlobalConfig(config) {
  db.prepare(`INSERT INTO settings (key, value) VALUES ('duo_config', ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value`).run(JSON.stringify(config));
}

function getDomainConfig(domainRow) {
  let parsed = domainRow ? domainRow.duo_config : {};
  if (typeof parsed === 'string') {
    try { parsed = JSON.parse(parsed || '{}'); } catch (e) { parsed = {}; }
  }
  return mergeConfig(parsed, DOMAIN_DEFAULTS);
}

// Combines global + per-domain settings into what's actually used for a
// given domain's login. `enforced` follows the domain's own mode unless
// it's "inherit", in which case the global mode decides. Credentials
// (Duo application client ID/secret/API host/redirect URL) come from the
// domain's own override only if it explicitly opted into one; otherwise
// the global Duo application is used.
function resolveEffective(domainRow) {
  const g = getGlobalConfig();
  const d = domainRow ? getDomainConfig(domainRow) : DOMAIN_DEFAULTS;

  let enforced;
  if (d.mode === 'enforced') enforced = true;
  else if (d.mode === 'disabled') enforced = false;
  else enforced = g.mode === 'enforced';

  const creds = d.credentialsOverride
    ? { clientId: d.clientId, clientSecretEnc: d.clientSecretEnc, apiHostname: d.apiHostname, redirectUrl: d.redirectUrl }
    : { clientId: g.clientId, clientSecretEnc: g.clientSecretEnc, apiHostname: g.apiHostname, redirectUrl: g.redirectUrl };

  return {
    enforced,
    clientId: creds.clientId,
    clientSecret: creds.clientSecretEnc ? cryptoHelper.decrypt(creds.clientSecretEnc) : '',
    apiHostname: creds.apiHostname,
    redirectUrl: creds.redirectUrl,
  };
}

function isConfigured(effective) {
  return !!(effective.clientId && effective.clientSecret && effective.apiHostname && effective.redirectUrl);
}

// Duo's SDK expects a bare hostname (api-XXXXXXXX.duosecurity.com). Admins
// often paste "https://api-XXXX.duosecurity.com/" - strip scheme, path,
// and whitespace so that doesn't produce a malformed request URL.
function normalizeHost(host) {
  return String(host || '').trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
}

function buildClient(effective) {
  const { Client } = require('@duosecurity/duo_universal');
  return new Client({
    clientId: String(effective.clientId || '').trim(),
    clientSecret: String(effective.clientSecret || '').trim(),
    apiHost: normalizeHost(effective.apiHostname),
    redirectUrl: String(effective.redirectUrl || '').trim(),
  });
}

// Starts a Duo Universal Prompt challenge for `username`. Returns the URL
// to redirect the browser to, plus the `state` value that must be matched
// back on the callback (Duo's CSRF protection).
async function startAuth(effective, username) {
  const client = buildClient(effective);
  const state = client.generateState();
  // In @duosecurity/duo_universal v3, createAuthUrl() is async (it signs the
  // request JWT with jose). Without `await` this returned a Promise, which
  // JSON-serialised to {} and made the browser navigate to "[object Object]".
  const authUrl = await client.createAuthUrl(username, state);
  if (typeof authUrl !== 'string' || !authUrl.startsWith('https://')) {
    throw new Error('Duo SDK did not return a valid authorization URL');
  }
  return { authUrl, state };
}

// Verifies the `duo_code` Duo sent back on the callback redirect. Throws
// on any failure (denied, expired, tampered, wrong user).
async function verifyAuth(effective, duoCode, username) {
  const client = buildClient(effective);
  return client.exchangeAuthorizationCodeFor2FAResult(duoCode, username);
}

async function healthCheck(effective) {
  const host = normalizeHost(effective.apiHostname);
  if (!/^api-[a-z0-9]+\.(duosecurity|duofederal)\.com$/i.test(host)) {
    throw new Error(`"${host}" doesn't look like a Duo API hostname (expected api-XXXXXXXX.duosecurity.com - it's on the application's details page, not the Admin Panel URL)`);
  }
  const client = buildClient(effective);
  return client.healthCheck();
}

// Strips the encrypted secret out of a config for API responses, replacing
// it with a boolean so the UI can show "a secret is set" without ever
// re-transmitting the (encrypted) value.
function sanitize(config) {
  const { clientSecretEnc, ...rest } = config;
  return { ...rest, hasClientSecret: !!clientSecretEnc };
}

module.exports = {
  getGlobalConfig, setGlobalConfig, getDomainConfig, resolveEffective, isConfigured,
  startAuth, verifyAuth, healthCheck, sanitize,
  GLOBAL_DEFAULTS, DOMAIN_DEFAULTS,
};
