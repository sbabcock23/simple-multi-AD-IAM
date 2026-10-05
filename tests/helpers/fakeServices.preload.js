'use strict';
/**
 * Test-only preload (node -r) that swaps the two third-party network SDKs the
 * app talks to for deterministic in-memory fakes, so the REAL application code
 * (src/ldap.js, src/duo.js, routes, middleware) runs end to end without an
 * Active Directory server or a Duo tenant.
 *
 *   ldapjs                        -> faked when FAKE_LDAP_FIXTURE is set
 *   @duosecurity/duo_universal    -> faked when FAKE_DUO=1
 *
 * FAKE_LDAP_FIXTURE : path to a JSON directory fixture (see directory.js)
 * FAKE_LDAP_LOG     : optional path; every connect/bind/search/modify is
 *                     appended as one JSON line so tests can assert on it.
 *
 * Nothing in here is shipped with the app and the app source is not modified.
 */
const Module = require('module');
const fs = require('fs');
const crypto = require('crypto');
const { EventEmitter } = require('events');

const fixturePath = process.env.FAKE_LDAP_FIXTURE;
const logPath = process.env.FAKE_LDAP_LOG;
let state = null;
if (fixturePath) state = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));

function log(entry) {
  if (!logPath) return;
  try { fs.appendFileSync(logPath, JSON.stringify({ t: Date.now(), ...entry }) + '\n'); } catch (e) { /* ignore */ }
}

const unesc = (s) => String(s).replace(/\\(5c|2a|28|29|00)/gi, (m, h) => (
  { '5c': '\\', '2a': '*', '28': '(', '29': ')', '00': '\0' }[h.toLowerCase()]
));
const eq = (a, b) => a != null && b != null && String(a).toLowerCase() === String(b).toLowerCase();
const inBase = (dn, base) => String(dn).toLowerCase().endsWith(String(base).toLowerCase());

function ldapError(name, code, message) {
  const e = new Error(message);
  e.name = name; e.code = code;
  return e;
}

function effectiveGroupDns(user) {
  const seen = new Set();
  const queue = [...(user.memberOf || [])];
  while (queue.length) {
    const dn = queue.shift();
    const key = dn.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    const group = (state.groups || []).find((g) => eq(g.dn, dn));
    if (group) queue.push(...(group.memberOf || []));
  }
  return seen;
}

function clauseValue(filter, attr) {
  const m = filter.match(new RegExp(`\\(${attr}=([^()]*)\\)`, 'i'));
  return m ? m[1] : null;
}

function runSearch(base, filter) {
  const users = (state.users || []).filter((u) => inBase(u.dn, base));

  if (/\(objectClass=group\)/i.test(filter)) {
    const names = [...filter.matchAll(/\(cn=([^()]*)\)/gi)].map((m) => unesc(m[1]).toLowerCase());
    return (state.groups || []).filter((g) => inBase(g.dn, base) && names.includes(g.cn.toLowerCase()));
  }

  const chain = '1.2.840.113556.1.4.1941';
  if (filter.includes(`memberOf:${chain}:=`)) {
    const groupDns = [...filter.matchAll(new RegExp(`memberOf:${chain.replace(/\./g, '\\.')}:=([^()]*)\\)`, 'g'))]
      .map((m) => unesc(m[1]).toLowerCase());
    const upn = unesc(clauseValue(filter, 'userPrincipalName') || '');
    const mail = unesc(clauseValue(filter, 'mail') || '');
    const sam = unesc(clauseValue(filter, 'sAMAccountName') || '');
    return users.filter((u) => {
      const idMatch = eq(upn, u.userPrincipalName) || eq(mail, u.mail) || eq(sam, u.sAMAccountName);
      if (!idMatch) return false;
      const eff = effectiveGroupDns(u);
      return groupDns.some((g) => eff.has(g));
    });
  }

  if (/\(distinguishedName=/i.test(filter)) {
    const id = unesc(clauseValue(filter, 'sAMAccountName') || '');
    return users.filter((u) => eq(u.sAMAccountName, id) || eq(u.userPrincipalName, id) || eq(u.dn, id));
  }

  if (/\(sAMAccountName=\*/i.test(filter)) {
    const raw = clauseValue(filter, 'sAMAccountName').replace(/^\*/, '').replace(/\*$/, '');
    const needle = unesc(raw).toLowerCase();
    return users.filter((u) => [u.sAMAccountName, u.cn, u.displayName, u.userPrincipalName]
      .some((v) => v && String(v).toLowerCase().includes(needle)));
  }

  if (/\(mail=/i.test(filter)) {
    const mail = unesc(clauseValue(filter, 'mail') || '');
    return users.filter((u) => eq(u.mail, mail));
  }
  return [];
}

function toEntry(obj) {
  const attributes = [];
  for (const type of ['sAMAccountName', 'cn', 'displayName', 'userPrincipalName', 'mail', 'lockoutTime', 'userAccountControl']) {
    if (obj[type] !== undefined && obj[type] !== null) attributes.push({ type, values: [String(obj[type])] });
  }
  return { pojo: { objectName: obj.dn, attributes } };
}

class FakeChange {
  constructor(opts) { this.operation = opts.operation; this.modification = opts.modification; }
}

class FakeClient extends EventEmitter {
  constructor(opts) {
    super();
    this.url = opts.url;
    this.boundUser = null;
    log({ op: 'connect', url: this.url });
    setImmediate(() => {
      if ((state.downUrls || []).includes(this.url)) {
        const err = new Error(`connect ECONNREFUSED ${this.url}`);
        err.code = 'ECONNREFUSED';
        this.emit('connectError', err);
      } else {
        this.emit('connect');
      }
    });
  }

  bind(identity, password, cb) {
    setImmediate(() => {
      const lc = String(identity).toLowerCase();
      const user = (state.users || []).find((u) => [
        u.dn, u.userPrincipalName, u.netbios && `${u.netbios}\\${u.sAMAccountName}`,
      ].filter(Boolean).some((x) => x.toLowerCase() === lc));
      const locked = user && user.lockoutTime && user.lockoutTime !== '0';
      const disabled = user && (parseInt(user.userAccountControl || '0', 10) & 2);
      const ok = !!user && user.password === password && !locked && !disabled;
      log({ op: 'bind', identity, ok });
      if (!ok) return cb(ldapError('InvalidCredentialsError', 49, '80090308: LdapErr: DSID-0C090447, data 52e'));
      this.boundUser = user;
      return cb(null);
    });
  }

  search(base, options, cb) {
    log({ op: 'search', by: this.boundUser && this.boundUser.dn, base, filter: options.filter });
    if (!this.boundUser) return cb(ldapError('OperationsError', 1, 'successful bind must be completed'));
    const res = new EventEmitter();
    cb(null, res);
    setImmediate(() => {
      let rows;
      try { rows = runSearch(base, options.filter); } catch (e) { return res.emit('error', e); }
      rows.slice(0, options.sizeLimit || 1000).forEach((r) => res.emit('searchEntry', toEntry(r)));
      return res.emit('end', { status: 0 });
    });
  }

  modify(dn, change, cb) {
    setImmediate(() => {
      const actor = this.boundUser;
      const target = (state.users || []).find((u) => eq(u.dn, dn));
      const attr = change.modification.type;
      const values = change.modification.values;
      const entry = { op: 'modify', by: actor && actor.dn, dn, attr };
      entry.values = values.map((v) => (Buffer.isBuffer(v) ? { base64: v.toString('base64') } : v));
      if (!actor || !actor.delegated) {
        log({ ...entry, ok: false });
        return cb(ldapError('InsufficientAccessRightsError', 50, '00000005: SecErr: DSID-03152492, problem 4003 (INSUFF_ACCESS_RIGHTS)'));
      }
      if (!target) {
        log({ ...entry, ok: false });
        return cb(ldapError('NoSuchObjectError', 32, 'no such object'));
      }
      if (attr === 'lockoutTime') target.lockoutTime = String(values[0]);
      if (attr === 'pwdLastSet') target.pwdLastSet = String(values[0]);
      if (attr === 'unicodePwd') target.password = Buffer.from(values[0]).toString('utf16le').replace(/^"|"$/g, '');
      log({ ...entry, ok: true });
      return cb(null);
    });
  }

  unbind(cb) { setImmediate(() => cb && cb()); }
  destroy() { /* nothing to tear down */ }
}

const fakeLdap = { createClient: (opts) => new FakeClient(opts), Change: FakeChange };

class FakeDuoClient {
  constructor(opts) { this.opts = opts; }
  generateState() { return `state-${crypto.randomBytes(8).toString('hex')}`; }
  async createAuthUrl(username, state2) {
    return `https://${this.opts.apiHost}/oauth/v1/authorize?client_id=${encodeURIComponent(this.opts.clientId)}`
      + `&state=${state2}&duo_uname=${encodeURIComponent(username)}`;
  }
  async exchangeAuthorizationCodeFor2FAResult(code, username) {
    if (code !== 'good-code') throw new Error('Invalid duo_code');
    return { preferred_username: username, auth_result: { status: 'allow' } };
  }
  async healthCheck() {
    if (this.opts.clientSecret === 'bad-secret') throw new Error('Invalid client secret');
    return { stat: 'OK' };
  }
}

const originalLoad = Module._load;
Module._load = function patchedLoad(request, parent, isMain) {
  if (request === 'ldapjs' && state) return fakeLdap;
  if (request === '@duosecurity/duo_universal' && process.env.FAKE_DUO === '1') return { Client: FakeDuoClient };
  return originalLoad.apply(this, arguments);
};
