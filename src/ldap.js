const ldap = require('ldapjs');
const net = require('net');
const tls = require('tls');
const { URL } = require('url');
const logger = require('./logger');

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
    logger.warn('ldap_client_error', {
      urls: (domainConfig.ldap_urls || []).join(','),
      ...logger.errInfo(err),
    });
  });
  client.on('connectError', (err) => {
    logger.warn('ldap_connect_error', {
      urls: (domainConfig.ldap_urls || []).join(','),
      ...logger.errInfo(err),
    });
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

// Binds as the signed-in end user's own AD account (their username/password,
// captured at login) and runs `fn` against that authenticated connection.
// There is no separate service account: every directory operation - search,
// unlock, or password reset - is performed with the acting user's own
// credentials, so their AD account must have the necessary delegated rights.
async function withUserBind(domainConfig, username, password, fn) {
  const client = createClient(domainConfig);
  try {
    logger.debug('ldap_bind_attempt', { username, urls: domainConfig.ldap_urls.join(',') });
    await bindClient(client, username, password);
    logger.debug('ldap_bind_success', { username });
    return await fn(client);
  } catch (err) {
    logger.warn('ldap_operation_failed', { username, ...logger.errInfo(err) });
    throw err;
  } finally {
    await unbindClient(client);
  }
}

async function authenticateUser(domainConfig, username, password) {
  await withUserBind(domainConfig, username, password, async () => true);
  return true;
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

async function searchUsers(domainConfig, username, password, query) {
  return withUserBind(domainConfig, username, password, async (client) => {
    const q = escapeFilter(query);
    const filter =
      `(&(objectCategory=person)(objectClass=user)` +
      `(|(sAMAccountName=*${q}*)(cn=*${q}*)(displayName=*${q}*)(userPrincipalName=*${q}*)))`;
    logger.debug('ldap_search', { baseDn: domainConfig.base_dn, filter });
    const results = await searchAsync(client, domainConfig.base_dn, {
      filter,
      scope: 'sub',
      attributes: USER_ATTRIBUTES,
      sizeLimit: 25,
    });
    return results.map(mapUser);
  });
}

async function getUserByIdentifier(domainConfig, username, password, identifier) {
  return withUserBind(domainConfig, username, password, async (client) => {
    const q = escapeFilter(identifier);
    const filter =
      `(&(objectCategory=person)(objectClass=user)` +
      `(|(sAMAccountName=${q})(userPrincipalName=${q})(distinguishedName=${q})))`;
    logger.debug('ldap_lookup', { baseDn: domainConfig.base_dn, filter });
    const results = await searchAsync(client, domainConfig.base_dn, {
      filter,
      scope: 'sub',
      attributes: USER_ATTRIBUTES,
      sizeLimit: 1,
    });
    return results[0] ? mapUser(results[0]) : null;
  });
}

function modify(client, dn, attribute, value) {
  return new Promise((resolve, reject) => {
    const change = new ldap.Change({
      operation: 'replace',
      modification: { type: attribute, values: [value] },
    });
    client.modify(dn, change, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

async function unlockUser(domainConfig, username, password, dn) {
  return withUserBind(domainConfig, username, password, (client) => {
    logger.debug('ldap_unlock', { targetDn: dn });
    return modify(client, dn, 'lockoutTime', '0');
  });
}

function encodeAdPassword(password) {
  // Active Directory expects the new password quoted and encoded as UTF-16LE.
  return Buffer.from(`"${password}"`, 'utf16le');
}

async function resetPassword(domainConfig, username, password, dn, newPassword, forceChangeAtLogon) {
  const allLdaps = domainConfig.ldap_urls.length > 0 &&
    domainConfig.ldap_urls.every((u) => u.toLowerCase().startsWith('ldaps://'));
  if (!allLdaps) {
    throw new Error('Password reset requires every configured LDAP server for this domain to use LDAPS.');
  }
  return withUserBind(domainConfig, username, password, async (client) => {
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

    // Same reasoning as the client 'error' listener above: an unhandled
    // socket 'error' event would otherwise crash the process.
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
  authenticateUser,
  searchUsers,
  getUserByIdentifier,
  unlockUser,
  resetPassword,
  testServers,
};
