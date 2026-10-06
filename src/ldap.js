const ldap = require('ldapjs');
const net = require('net');
const tls = require('tls');
const { URL } = require('url');
const logger = require('./logger');
const cryptoHelper = require('./crypto');

// Creates a client bound to a single LDAP server URL. Kept internal -
// callers should go through connectClient() below, which is what actually
// walks the domain's configured server list on failure.
function createClientForUrl(url, domainConfig) {
  const client = ldap.createClient({
    url,
    tlsOptions: { rejectUnauthorized: !!domainConfig.tls_reject_unauthorized },
    timeout: 8000,
    connectTimeout: 8000,
    // We do our own failover across domainConfig.ldap_urls in connectClient().
    // Letting ldapjs's internal reconnect loop run as well would just retry
    // this same dead server instead of moving on to the next one.
    reconnect: false,
  });

  // IMPORTANT: ldapjs clients are EventEmitters. If the underlying socket
  // errors (server unreachable, connection dropped mid-operation, TLS
  // handshake failure, etc.) and nothing is listening for the client's
  // 'error' event, Node throws that error as an uncaught exception and can
  // crash the entire process - taking down every user's session, not just
  // the one request that hit the problem. This listener is what prevents
  // that: we log the failure and let the in-flight bind/search/modify
  // promise reject normally instead.
  client.on('error', (err) => {
    logger.warn('ldap_client_error', { url, ...logger.errInfo(err) });
  });

  return client;
}

// Error codes/names that indicate the *server itself* couldn't be reached
// (host down, refused, timed out, DNS failure, etc.) as opposed to an error
// that came back from a server that IS up and answering (bad credentials,
// protocol violation, ...). Only the former should cause us to move on to
// the next configured LDAP server - the latter is a definitive answer from
// a live server and retrying it against another replica wouldn't change it.
const CONNECTIVITY_ERROR_CODES = new Set([
  'EHOSTUNREACH', 'ECONNREFUSED', 'ENETUNREACH', 'ETIMEDOUT',
  'ECONNRESET', 'EAI_AGAIN', 'ENOTFOUND', 'EPIPE',
]);

function isConnectivityError(err) {
  if (!err) return false;
  if (CONNECTIVITY_ERROR_CODES.has(err.code)) return true;
  // ldapjs wraps connect-phase failures (including its own connect timeout)
  // in these error types regardless of the underlying socket error code.
  if (err.name === 'ConnectionError' || err.name === 'TimeoutError') return true;
  return false;
}

// Opens a live, connected client against a domain's configured LDAP
// servers, trying each URL in domainConfig.ldap_urls **in order** and
// falling over to the next one whenever a server is unreachable. There can
// be two or more servers configured for a domain, and any of them may be
// down at a given time, so every URL in the list gets a chance before we
// give up.
//
// Note: ldapjs's own built-in support for passing an array of URLs to
// createClient() does NOT reliably do this - it can surface the first
// server's connection error to the caller (e.g. to an in-flight bind())
// before it has gotten around to trying the next URL in the array, so a
// single unreachable server can fail a login even when a working server is
// configured right after it. Failover across the pool is therefore handled
// explicitly here instead of being delegated to ldapjs.
// Remembers, per domain, which URL last connected successfully. Every
// directory operation (login, unlock, reset password, search, ...) opens
// its own short-lived connection via connectClient(), so without this a
// domain with a down first server pays the full connectTimeout on that
// dead server again on *every single action* - which, across a login
// followed by a lookup-then-unlock or lookup-then-reset (two LDAP
// connections each), is enough added latency that those actions can
// appear to hang or fail even though they would eventually succeed. Once
// any connection succeeds against a given URL, that URL is tried first on
// subsequent calls for the same domain, so only the very first request
// after a server goes down pays the timeout; everything after that goes
// straight to the known-good server. If the remembered URL stops working,
// it's dropped from the cache and the full list (in configured order) is
// tried again.
const lastGoodUrlByDomain = new Map();

function domainCacheKey(domainConfig) {
  return domainConfig && domainConfig.id != null
    ? `id:${domainConfig.id}`
    : `urls:${(domainConfig.ldap_urls || []).join(',')}`;
}

function connectClient(domainConfig) {
  const configuredUrls = domainConfig.ldap_urls || [];
  if (!configuredUrls.length) {
    return Promise.reject(new Error('No LDAP servers configured for this domain'));
  }

  const cacheKey = domainCacheKey(domainConfig);
  const lastGood = lastGoodUrlByDomain.get(cacheKey);
  const urls = lastGood && configuredUrls.includes(lastGood)
    ? [lastGood, ...configuredUrls.filter((u) => u !== lastGood)]
    : configuredUrls;

  return new Promise((resolve, reject) => {
    let index = 0;
    let lastErr = null;

    const attemptNext = () => {
      if (index >= urls.length) {
        reject(lastErr || new Error('All configured LDAP servers are unreachable'));
        return;
      }
      const url = urls[index++];
      const client = createClientForUrl(url, domainConfig);
      let settled = false;

      const cleanup = () => {
        client.removeListener('connect', onConnect);
        client.removeListener('connectError', onConnectError);
      };

      const onConnect = () => {
        if (settled) return;
        settled = true;
        cleanup();
        lastGoodUrlByDomain.set(cacheKey, url);
        resolve(client);
      };

      const onConnectError = (err) => {
        if (settled) return;
        settled = true;
        cleanup();
        logger.warn('ldap_connect_error', { url, ...logger.errInfo(err) });
        lastErr = err;
        if (lastGoodUrlByDomain.get(cacheKey) === url) {
          lastGoodUrlByDomain.delete(cacheKey);
        }
        try { client.destroy(); } catch (e) { /* already gone */ }
        if (isConnectivityError(err)) {
          attemptNext();
        } else {
          // The server answered but something else went wrong (e.g. TLS
          // config mismatch) - that's not something the next server in the
          // list will fix differently, so surface it immediately.
          reject(err);
        }
      };

      client.on('connect', onConnect);
      client.on('connectError', onConnectError);
    };

    attemptNext();
  });
}

function bindClient(client, dn, password) {
  return new Promise((resolve, reject) => {
    client.bind(dn, password, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

function unbindClient(client) {
  return new Promise((resolve) => {
    client.unbind(() => resolve());
  });
}

// Binds using an already-known identity string (DN, UPN, or
// DOMAIN\sAMAccountName) and runs `fn` against that authenticated
// connection. There is no separate service account: every directory
// operation - search, unlock, or password reset - is performed with the
// acting user's own credentials, so their AD account must have the
// necessary delegated rights.
async function withUserBind(domainConfig, bindIdentity, password, fn) {
  const client = await connectClient(domainConfig);
  try {
    logger.debug('ldap_bind_attempt', { bindIdentity, urls: domainConfig.ldap_urls.join(',') });
    await bindClient(client, bindIdentity, password);
    logger.debug('ldap_bind_success', { bindIdentity });
    return await fn(client);
  } catch (err) {
    logger.warn('ldap_operation_failed', { bindIdentity, ...logger.errInfo(err) });
    throw err;
  } finally {
    await unbindClient(client);
  }
}

// Runs a search and resolves with every entry received. The returned array
// has a non-enumerable `truncated` flag that is true when the server stopped
// early because the sizeLimit was hit (LDAP result code 4 - AD reports this
// as an *error* even though the entries it did send are perfectly valid).
// Treating that as a hard failure is what made broad queries such as "ma"
// fail with "Size Limit Exceeded" while narrower ones succeeded: callers
// get the partial page and decide whether to tell the user it was capped.
function isSizeLimitError(err) {
  return !!err && (err.name === 'SizeLimitExceededError' || err.code === 4 ||
    /size limit exceeded/i.test(err.message || ''));
}

function searchAsync(client, base, options) {
  return new Promise((resolve, reject) => {
    const results = [];
    let truncated = false;
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      Object.defineProperty(results, 'truncated', { value: truncated, enumerable: false });
      resolve(results);
    };
    client.search(base, options, (err, res) => {
      if (err) {
        if (isSizeLimitError(err)) { truncated = true; return finish(); }
        return reject(err);
      }
      res.on('searchEntry', (entry) => {
        results.push(entryToObject(entry));
      });
      res.on('error', (err2) => {
        if (isSizeLimitError(err2)) { truncated = true; return finish(); }
        if (!done) { done = true; reject(err2); }
      });
      res.on('end', finish);
    });
  });
}

function entryToObject(entry) {
  const pojo = entry.pojo || entry;
  const obj = { dn: pojo.objectName || entry.objectName };
  const attrs = pojo.attributes || [];
  for (const a of attrs) {
    const vals = a.values || a.vals || [];
    obj[a.type] = vals.length === 1 ? vals[0] : vals;
  }
  return obj;
}

function escapeFilter(str) {
  return String(str).replace(/[\\*()\0]/g, (c) => {
    switch (c) {
      case '\\': return '\\5c';
      case '*': return '\\2a';
      case '(': return '\\28';
      case ')': return '\\29';
      case '\0': return '\\00';
      default: return c;
    }
  });
}

// lockoutTime stays non-zero after a lockout *expires* on its own, so when
// AD supplies the constructed msDS-User-Account-Control-Computed attribute
// (UF_LOCKOUT = 0x10) it is the authoritative answer; otherwise fall back to
// lockoutTime.
function isLocked(u) {
  const computed = u['msDS-User-Account-Control-Computed'];
  if (computed !== undefined && computed !== '') {
    return !!(parseInt(computed, 10) & 0x10);
  }
  return !!u.lockoutTime && u.lockoutTime !== '0';
}

function mapUser(u) {
  const uac = parseInt(u.userAccountControl || '0', 10);
  return {
    dn: u.dn,
    sAMAccountName: u.sAMAccountName,
    cn: u.cn,
    displayName: u.displayName || u.cn,
    userPrincipalName: u.userPrincipalName,
    mail: u.mail,
    locked: isLocked(u),
    disabled: !!(uac & 2),
  };
}

const USER_ATTRIBUTES = ['dn', 'sAMAccountName', 'cn', 'displayName', 'userPrincipalName', 'lockoutTime', 'userAccountControl', 'mail', 'msDS-User-Account-Control-Computed'];

// LDAP_MATCHING_RULE_IN_CHAIN: Active Directory's "walk the whole nested
// group chain" operator. Used here so a helpdesk account that's a member of
// an allowed group indirectly (nested inside another group) is recognized,
// not just direct members.
const MATCHING_RULE_IN_CHAIN = '1.2.840.113556.1.4.1941';

async function resolveGroupDns(client, baseDn, groupNames) {
  const names = (groupNames || []).map((n) => String(n).trim()).filter(Boolean);
  if (!names.length) return [];
  const orClauses = names.map((n) => `(cn=${escapeFilter(n)})`).join('');
  const filter = `(&(objectClass=group)(|${orClauses}))`;
  const results = await searchAsync(client, baseDn, { filter, scope: 'sub', attributes: ['dn', 'cn'], sizeLimit: names.length + 5 });
  return results.map((r) => r.dn);
}

// Resolves "this email address -> this AD account" using the domain's
// optional, narrowly-scoped lookup account. This is the ONLY thing that
// account is ever used for - it never performs a search-for-unlock,
// unlock, or password reset; those always run as the signed-in user, once
// bindWithFallback below has established their real identity. Returns null
// (never throws for "not found") so callers can fall through to other
// resolution strategies; genuine bind/connection errors do still throw.
async function lookupByMail(domainConfig, mailValue) {
  if (!domainConfig.lookup_bind_dn || !domainConfig.lookup_bind_password_enc) return null;
  const client = await connectClient(domainConfig);
  try {
    const lookupPassword = cryptoHelper.decrypt(domainConfig.lookup_bind_password_enc);
    await bindClient(client, domainConfig.lookup_bind_dn, lookupPassword);
    const q = escapeFilter(mailValue);
    const filter = `(&(objectClass=user)(objectCategory=person)(mail=${q}))`;
    logger.debug('ldap_mail_lookup', { baseDn: domainConfig.base_dn });
    const results = await searchAsync(client, domainConfig.base_dn, {
      filter, scope: 'sub', attributes: ['dn', 'userPrincipalName', 'sAMAccountName'], sizeLimit: 1,
    });
    return results[0] ? { dn: results[0].dn, userPrincipalName: results[0].userPrincipalName, sAMAccountName: results[0].sAMAccountName } : null;
  } finally {
    await unbindClient(client);
  }
}

// Tries to authenticate with the value the person typed - which may be
// their userPrincipalName, their email address (the AD `mail` attribute,
// which can live in a totally different domain than the UPN or the AD
// domain itself), or, when the domain has a NetBIOS name configured, their
// sAMAccountName. AD's simple bind only natively accepts a DN, a UPN, or
// "NETBIOS\sAMAccountName" - it does not accept an arbitrary "mail" value
// directly - so up to three things are tried in order, stopping at the
// first that authenticates successfully:
//   1. Bind with exactly what was typed (works whenever it's already a
//      valid UPN, or whenever mail happens to equal the UPN).
//   2. If a lookup account is configured for this domain: resolve the real
//      account by its actual `mail` attribute, then bind with its DN. This
//      is the authoritative path for "login by email" when the email
//      domain differs from both the UPN suffix and the AD domain.
//   3. If a NetBIOS domain name is configured: bind as
//      NETBIOS\<part before '@'>, assuming that's the sAMAccountName - a
//      fallback heuristic for when no lookup account is configured.
// Once authenticateAndAuthorize() below finds the actual user object (by
// UPN, mail, or sAMAccountName), its DN is used for every subsequent bind
// in the session, regardless of which identifier the person originally
// typed or which of the methods above resolved it.
async function bindWithFallback(domainConfig, typedIdentifier, password) {
  const atIdx = typedIdentifier.indexOf('@');
  const localPart = atIdx > -1 ? typedIdentifier.slice(0, atIdx) : typedIdentifier;

  const attempts = [typedIdentifier];
  if (domainConfig.lookup_bind_dn) {
    try {
      const found = await lookupByMail(domainConfig, typedIdentifier);
      if (found) attempts.push(found.dn);
      else logger.debug('ldap_mail_lookup_no_match', { typedIdentifier });
    } catch (err) {
      logger.warn('ldap_mail_lookup_failed', { typedIdentifier, ...logger.errInfo(err) });
    }
  }
  if (domainConfig.netbios_name) {
    attempts.push(`${domainConfig.netbios_name}\\${localPart}`);
  }

  // Connect once (with failover across domainConfig.ldap_urls) and reuse
  // that single live connection for every identity attempt below, rather
  // than reconnecting from scratch per attempt - which previously meant
  // re-discovering the same dead first server once per attempt.
  const client = await connectClient(domainConfig);
  let lastErr = null;
  for (const attempt of attempts) {
    try {
      logger.debug('ldap_bind_attempt', { bindIdentity: attempt });
      await bindClient(client, attempt, password);
      logger.debug('ldap_bind_success', { bindIdentity: attempt });
      return { client, localPart };
    } catch (err) {
      lastErr = err;
    }
  }
  await unbindClient(client);
  throw lastErr || new Error('Authentication failed');
}

// Authenticates the typed identifier/password against a domain, then
// verifies the resulting account is a (possibly nested) member of at least
// one of the domain's allowed AD groups. Returns the matched user object on
// success (its `dn` is what subsequent operations bind with), or throws
// with a `code` describing why it was rejected.
async function authenticateAndAuthorize(domainConfig, typedIdentifier, password, allowedGroupNames) {
  const { client, localPart } = await bindWithFallback(domainConfig, typedIdentifier, password);
  try {
    const groupDns = await resolveGroupDns(client, domainConfig.base_dn, allowedGroupNames);
    if (!groupDns.length) {
      throw Object.assign(new Error('No configured allowed groups could be found in this domain'), { code: 'NO_ALLOWED_GROUPS' });
    }

    const q = escapeFilter(typedIdentifier);
    const qLocal = escapeFilter(localPart);
    const memberClauses = groupDns.map((dn) => `(memberOf:${MATCHING_RULE_IN_CHAIN}:=${escapeFilter(dn)})`).join('');
    const filter =
      `(&(objectClass=user)(objectCategory=person)` +
      `(|(userPrincipalName=${q})(mail=${q})(sAMAccountName=${qLocal}))` +
      `(|${memberClauses}))`;

    logger.debug('ldap_authorize_search', { baseDn: domainConfig.base_dn, groupCount: groupDns.length });
    const results = await searchAsync(client, domainConfig.base_dn, {
      filter, scope: 'sub', attributes: USER_ATTRIBUTES, sizeLimit: 1,
    });
    if (!results[0]) {
      throw Object.assign(new Error('User not found, or not a member of an allowed group'), { code: 'NOT_AUTHORIZED' });
    }
    return mapUser(results[0]);
  } finally {
    await unbindClient(client);
  }
}

const SEARCH_LIMIT = 25;
const LOCKED_LIST_LIMIT = 200;

// Returns { users, truncated }. `truncated` is true when more accounts
// matched than the limit allows, so the UI can ask for a narrower search.
async function searchUsers(domainConfig, bindDn, password, query) {
  return withUserBind(domainConfig, bindDn, password, async (client) => {
    const q = escapeFilter(query);
    const filter =
      `(&(objectCategory=person)(objectClass=user)` +
      `(|(sAMAccountName=*${q}*)(cn=*${q}*)(displayName=*${q}*)(userPrincipalName=*${q}*)))`;
    logger.debug('ldap_search', { baseDn: domainConfig.base_dn, filter });
    const results = await searchAsync(client, domainConfig.base_dn, {
      filter, scope: 'sub', attributes: USER_ATTRIBUTES, sizeLimit: SEARCH_LIMIT,
    });
    return { users: results.map(mapUser), truncated: !!results.truncated };
  });
}

// Currently locked-out accounts, for pre-populating the unlock list.
// (lockoutTime>=1) is evaluated server-side; accounts whose lockout has
// since expired are then dropped using the computed lockout flag.
async function listLockedUsers(domainConfig, bindDn, password) {
  return withUserBind(domainConfig, bindDn, password, async (client) => {
    const filter = '(&(objectCategory=person)(objectClass=user)(lockoutTime>=1))';
    logger.debug('ldap_list_locked', { baseDn: domainConfig.base_dn });
    const results = await searchAsync(client, domainConfig.base_dn, {
      filter, scope: 'sub', attributes: USER_ATTRIBUTES, sizeLimit: LOCKED_LIST_LIMIT,
    });
    const users = results.map(mapUser).filter((u) => u.locked)
      .sort((a, b) => String(a.displayName || '').localeCompare(String(b.displayName || '')));
    return { users, truncated: !!results.truncated };
  });
}

async function getUserByIdentifier(domainConfig, bindDn, password, identifier) {
  return withUserBind(domainConfig, bindDn, password, async (client) => {
    const q = escapeFilter(identifier);
    const filter =
      `(&(objectCategory=person)(objectClass=user)` +
      `(|(sAMAccountName=${q})(userPrincipalName=${q})(distinguishedName=${q})))`;
    logger.debug('ldap_lookup', { baseDn: domainConfig.base_dn, filter });
    const results = await searchAsync(client, domainConfig.base_dn, {
      filter, scope: 'sub', attributes: USER_ATTRIBUTES, sizeLimit: 1,
    });
    return results[0] ? mapUser(results[0]) : null;
  });
}

function modify(client, dn, attribute, value) {
  return new Promise((resolve, reject) => {
    const change = new ldap.Change({ operation: 'replace', modification: { type: attribute, values: [value] } });
    client.modify(dn, change, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

async function unlockUser(domainConfig, bindDn, password, dn) {
  return withUserBind(domainConfig, bindDn, password, (client) => {
    logger.debug('ldap_unlock', { targetDn: dn });
    return modify(client, dn, 'lockoutTime', '0');
  });
}

function encodeAdPassword(password) {
  // Active Directory expects the new password quoted and encoded as UTF-16LE.
  return Buffer.from(`"${password}"`, 'utf16le');
}

async function resetPassword(domainConfig, bindDn, password, dn, newPassword, forceChangeAtLogon) {
  const allLdaps = domainConfig.ldap_urls.length > 0 &&
    domainConfig.ldap_urls.every((u) => u.toLowerCase().startsWith('ldaps://'));
  if (!allLdaps) {
    throw new Error('Password reset requires every configured LDAP server for this domain to use LDAPS.');
  }
  return withUserBind(domainConfig, bindDn, password, async (client) => {
    logger.debug('ldap_reset_password', { targetDn: dn, forceChangeAtLogon: !!forceChangeAtLogon });
    await new Promise((resolve, reject) => {
      const change = new ldap.Change({
        operation: 'replace',
        modification: { type: 'unicodePwd', values: [encodeAdPassword(newPassword)] },
      });
      client.modify(dn, change, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
    if (forceChangeAtLogon) {
      await modify(client, dn, 'pwdLastSet', '0');
    }
  });
}

// Credential-free reachability check for a list of LDAP server URLs: opens a
// raw TCP/TLS socket to each host:port so admins can verify connectivity
// before anyone has to sign in against it.
function testServers(ldapUrls, tlsRejectUnauthorized) {
  return Promise.all((ldapUrls || []).map((u) => testOneServer(u, tlsRejectUnauthorized)));
}

function testOneServer(urlStr, tlsRejectUnauthorized) {
  return new Promise((resolve) => {
    let parsed;
    try {
      parsed = new URL(urlStr);
    } catch (e) {
      return resolve({ url: urlStr, ok: false, error: 'Invalid URL' });
    }
    const isTls = parsed.protocol === 'ldaps:';
    const port = parsed.port ? parseInt(parsed.port, 10) : (isTls ? 636 : 389);
    const host = parsed.hostname;
    const timeoutMs = 5000;
    let settled = false;
    const finish = (result) => {
      if (!settled) { settled = true; resolve(result); }
      if (!result.ok) logger.warn('ldap_test_connection_failed', { url: urlStr, error: result.error });
    };

    let socket;
    try {
      socket = isTls
        ? tls.connect({ host, port, rejectUnauthorized: !!tlsRejectUnauthorized, timeout: timeoutMs }, () => {
            socket.end();
            finish({ url: urlStr, ok: true });
          })
        : net.createConnection({ host, port, timeout: timeoutMs }, () => {
            socket.end();
            finish({ url: urlStr, ok: true });
          });
    } catch (e) {
      return finish({ url: urlStr, ok: false, error: e.message });
    }

    socket.on('error', (err) => {
      finish({ url: urlStr, ok: false, error: err.message });
    });
    socket.on('timeout', () => {
      socket.destroy();
      finish({ url: urlStr, ok: false, error: 'Connection timed out' });
    });
  });
}

module.exports = {
  authenticateAndAuthorize,
  lookupByMail,
  searchUsers,
  listLockedUsers,
  getUserByIdentifier,
  unlockUser,
  resetPassword,
  testServers,
};
