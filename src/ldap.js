const ldap = require('ldapjs');
const net = require('net');
const tls = require('tls');
const { URL } = require('url');
const logger = require('./logger');
const cryptoHelper = require('./crypto');

// Creates a client configured for a domain's full list of LDAP servers.
// ldapjs accepts an array of URLs directly and handles failover between them.
function createClient(domainConfig) {
  const client = ldap.createClient({
    url: domainConfig.ldap_urls,
    tlsOptions: { rejectUnauthorized: !!domainConfig.tls_reject_unauthorized },
    timeout: 8000,
    connectTimeout: 8000,
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
    logger.warn('ldap_client_error', { urls: (domainConfig.ldap_urls || []).join(','), ...logger.errInfo(err) });
  });
  client.on('connectError', (err) => {
    logger.warn('ldap_connect_error', { urls: (domainConfig.ldap_urls || []).join(','), ...logger.errInfo(err) });
  });

  return client;
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
  const client = createClient(domainConfig);
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

function searchAsync(client, base, options) {
  return new Promise((resolve, reject) => {
    const results = [];
    client.search(base, options, (err, res) => {
      if (err) return reject(err);
      res.on('searchEntry', (entry) => {
        results.push(entryToObject(entry));
      });
      res.on('error', (err2) => reject(err2));
      res.on('end', () => resolve(results));
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

function mapUser(u) {
  const uac = parseInt(u.userAccountControl || '0', 10);
  return {
    dn: u.dn,
    sAMAccountName: u.sAMAccountName,
    cn: u.cn,
    displayName: u.displayName || u.cn,
    userPrincipalName: u.userPrincipalName,
    mail: u.mail,
    locked: !!u.lockoutTime && u.lockoutTime !== '0',
    disabled: !!(uac & 2),
  };
}

const USER_ATTRIBUTES = ['dn', 'sAMAccountName', 'cn', 'displayName', 'userPrincipalName', 'lockoutTime', 'userAccountControl', 'mail'];

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
  const client = createClient(domainConfig);
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

  let lastErr = null;
  for (const attempt of attempts) {
    const client = createClient(domainConfig);
    try {
      logger.debug('ldap_bind_attempt', { bindIdentity: attempt });
      await bindClient(client, attempt, password);
      logger.debug('ldap_bind_success', { bindIdentity: attempt });
      return { client, localPart };
    } catch (err) {
      lastErr = err;
      await unbindClient(client);
    }
  }
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

async function searchUsers(domainConfig, bindDn, password, query) {
  return withUserBind(domainConfig, bindDn, password, async (client) => {
    const q = escapeFilter(query);
    const filter =
      `(&(objectCategory=person)(objectClass=user)` +
      `(|(sAMAccountName=*${q}*)(cn=*${q}*)(displayName=*${q}*)(userPrincipalName=*${q}*)))`;
    logger.debug('ldap_search', { baseDn: domainConfig.base_dn, filter });
    const results = await searchAsync(client, domainConfig.base_dn, {
      filter, scope: 'sub', attributes: USER_ATTRIBUTES, sizeLimit: 25,
    });
    return results.map(mapUser);
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
  getUserByIdentifier,
  unlockUser,
  resetPassword,
  testServers,
};
