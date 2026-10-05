'use strict';
/**
 * Runs the REAL src/ldap.js against the in-memory fake directory. This is the
 * most logic-dense module (login resolution, nested-group authorisation,
 * failover, filter escaping, AD password encoding), so it gets thorough
 * coverage here without needing a domain controller.
 */
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { buildDirectory, contosoDomain, fabrikamDomain, PASSWORDS, CONTOSO } = require('../helpers/directory');
const { TEST_ENCRYPTION_KEY } = require('../helpers/env');

const work = fs.mkdtempSync(path.join(os.tmpdir(), 'iam-ldap-'));
const logFile = path.join(work, 'ldap.log');
fs.writeFileSync(logFile, '');
fs.writeFileSync(path.join(work, 'dir.json'), JSON.stringify(buildDirectory()));
Object.assign(process.env, {
  FAKE_LDAP_FIXTURE: path.join(work, 'dir.json'),
  FAKE_LDAP_LOG: logFile,
  ENCRYPTION_KEY: TEST_ENCRYPTION_KEY,
  LOG_LEVEL: 'silent',
});
require('../helpers/fakeServices.preload.js');

const ldap = require('../../src/ldap');
const cryptoHelper = require('../../src/crypto');

const readLog = () => fs.readFileSync(logFile, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
const contoso = () => ({ id: 1, ...contosoDomain(), tls_reject_unauthorized: false });
const fabrikam = () => {
  const d = fabrikamDomain();
  return { id: 2, ...d, lookup_bind_password_enc: cryptoHelper.encrypt(d.lookup_bind_password) };
};

describe('src/ldap against a fake directory', () => {
  after(() => fs.rmSync(work, { recursive: true, force: true }));

  describe('authenticateAndAuthorize', () => {
    it('authenticates by UPN and returns the account DN', async () => {
      const u = await ldap.authenticateAndAuthorize(contoso(), 'helpdesk1@contoso.test', PASSWORDS.helpdesk1, ['Helpdesk']);
      assert.equal(u.sAMAccountName, 'helpdesk1');
      assert.equal(u.dn, `CN=Help Desk One,OU=Users,${CONTOSO}`);
      assert.equal(u.locked, false);
      assert.equal(u.disabled, false);
    });

    it('authorises members of a NESTED group via the in-chain matching rule', async () => {
      const u = await ldap.authenticateAndAuthorize(contoso(), 'nested1@contoso.test', PASSWORDS.nested1, ['Helpdesk']);
      assert.equal(u.sAMAccountName, 'nested1');
      const searched = readLog().filter((e) => e.op === 'search').map((e) => e.filter).join('\n');
      assert.match(searched, /memberOf:1\.2\.840\.113556\.1\.4\.1941:=/);
    });

    it('rejects a wrong password', async () => {
      await assert.rejects(
        ldap.authenticateAndAuthorize(contoso(), 'helpdesk1@contoso.test', 'wrong', ['Helpdesk']),
        (e) => e.name === 'InvalidCredentialsError'
      );
    });

    it('rejects valid credentials when the account is not in an allowed group (NOT_AUTHORIZED)', async () => {
      await assert.rejects(
        ldap.authenticateAndAuthorize(contoso(), 'outsider1@contoso.test', PASSWORDS.outsider1, ['Helpdesk']),
        (e) => e.code === 'NOT_AUTHORIZED'
      );
    });

    it('fails closed with NO_ALLOWED_GROUPS when none of the configured groups exist', async () => {
      await assert.rejects(
        ldap.authenticateAndAuthorize(contoso(), 'helpdesk1@contoso.test', PASSWORDS.helpdesk1, ['Ghost Group']),
        (e) => e.code === 'NO_ALLOWED_GROUPS'
      );
    });

    it('fails closed when the allowed-group list is empty', async () => {
      await assert.rejects(
        ldap.authenticateAndAuthorize(contoso(), 'helpdesk1@contoso.test', PASSWORDS.helpdesk1, []),
        (e) => e.code === 'NO_ALLOWED_GROUPS'
      );
    });

    it('falls back to NETBIOS\\sAMAccountName when the typed UPN does not match the real one', async () => {
      const u = await ldap.authenticateAndAuthorize(contoso(), 'legacy1@contoso.test', PASSWORDS.legacy1, ['Helpdesk']);
      assert.equal(u.sAMAccountName, 'legacy1');
      assert.ok(readLog().some((e) => e.op === 'bind' && e.identity === 'CONTOSO\\legacy1' && e.ok));
    });

    it('does NOT use the NetBIOS fallback when no NetBIOS name is configured', async () => {
      const d = { ...contoso(), netbios_name: null };
      await assert.rejects(ldap.authenticateAndAuthorize(d, 'legacy1@contoso.test', PASSWORDS.legacy1, ['Helpdesk']));
    });

    it('resolves a login by e-mail address through the lookup account', async () => {
      const u = await ldap.authenticateAndAuthorize(fabrikam(), 'amy@fabrikam.com', PASSWORDS.amy, ['Support']);
      assert.equal(u.sAMAccountName, 'amy');
      assert.equal(u.mail, 'amy@fabrikam.com');
    });

    it('cannot sign in by e-mail without a lookup account or NetBIOS name (UPN differs)', async () => {
      const d = { ...fabrikam(), lookup_bind_dn: null, lookup_bind_password_enc: null, netbios_name: null };
      await assert.rejects(ldap.authenticateAndAuthorize(d, 'amy@fabrikam.com', PASSWORDS.amy, ['Support']));
    });

    it('refuses locked and disabled accounts at bind time', async () => {
      const allow = ['Helpdesk'];
      await assert.rejects(ldap.authenticateAndAuthorize(contoso(), 'locked.user@contoso.test', 'Whatever1!', allow));
      await assert.rejects(ldap.authenticateAndAuthorize(contoso(), 'disabled.user@contoso.test', 'Whatever3!', allow));
    });

    it('does not leak users across domains (search is scoped to the base DN)', async () => {
      await assert.rejects(
        ldap.authenticateAndAuthorize({ ...contoso(), base_dn: 'DC=fabrikam,DC=test' }, 'helpdesk1@contoso.test', PASSWORDS.helpdesk1, ['Support'])
      );
    });
  });

  describe('server failover', () => {
    it('moves on to the next server when the first is unreachable', async () => {
      const d = { ...contoso(), id: 77, ldap_urls: ['ldaps://dead.contoso.test:636', 'ldaps://dc2.contoso.test:636'] };
      const u = await ldap.authenticateAndAuthorize(d, 'helpdesk1@contoso.test', PASSWORDS.helpdesk1, ['Helpdesk']);
      assert.equal(u.sAMAccountName, 'helpdesk1');
      const connects = readLog().filter((e) => e.op === 'connect').map((e) => e.url);
      assert.ok(connects.includes('ldaps://dead.contoso.test:636'));
      assert.ok(connects.includes('ldaps://dc2.contoso.test:636'));
    });

    it('remembers the last good server and tries it first next time', async () => {
      const d = { ...contoso(), id: 78, ldap_urls: ['ldaps://dead.contoso.test:636', 'ldaps://dc2.contoso.test:636'] };
      await ldap.searchUsers(d, `CN=Help Desk One,OU=Users,${CONTOSO}`, PASSWORDS.helpdesk1, 'help');
      const before = readLog().length;
      await ldap.searchUsers(d, `CN=Help Desk One,OU=Users,${CONTOSO}`, PASSWORDS.helpdesk1, 'help');
      const second = readLog().slice(before).filter((e) => e.op === 'connect');
      assert.equal(second[0].url, 'ldaps://dc2.contoso.test:636');
      assert.ok(!second.some((e) => e.url.includes('dead')));
    });

    it('rejects when every server is down', async () => {
      const d = { ...contoso(), id: 79, ldap_urls: ['ldaps://dead.contoso.test:636'] };
      await assert.rejects(
        ldap.authenticateAndAuthorize(d, 'helpdesk1@contoso.test', PASSWORDS.helpdesk1, ['Helpdesk']),
        (e) => e.code === 'ECONNREFUSED'
      );
    });

    it('rejects when no servers are configured', async () => {
      await assert.rejects(
        ldap.searchUsers({ ...contoso(), ldap_urls: [] }, 'x', 'y', 'abc'),
        /No LDAP servers configured/
      );
    });
  });

  describe('searchUsers / getUserByIdentifier', () => {
    const bindDn = `CN=Help Desk One,OU=Users,${CONTOSO}`;

    it('finds users by substring across name attributes and maps the fields', async () => {
      const rows = await ldap.searchUsers(contoso(), bindDn, PASSWORDS.helpdesk1, 'locked');
      assert.equal(rows.length, 1);
      assert.equal(rows[0].sAMAccountName, 'locked.user');
      assert.equal(rows[0].locked, true);
      assert.equal(rows[0].disabled, false);
    });

    it('reports disabled accounts via userAccountControl bit 2', async () => {
      const rows = await ldap.searchUsers(contoso(), bindDn, PASSWORDS.helpdesk1, 'disabled');
      assert.equal(rows[0].disabled, true);
    });

    it('escapes LDAP filter metacharacters (no filter injection)', async () => {
      const before = readLog().length;
      const rows = await ldap.searchUsers(contoso(), bindDn, PASSWORDS.helpdesk1, '*)(uid=*))(|(cn=*');
      assert.deepEqual(rows, []);
      const filter = readLog().slice(before).find((e) => e.op === 'search').filter;
      assert.ok(!filter.includes('(uid=*'), `unescaped injection in filter: ${filter}`);
      assert.match(filter, /\\2a\\29\\28uid=\\2a/);
    });

    it('escapes backslashes and NUL', async () => {
      const before = readLog().length;
      await ldap.searchUsers(contoso(), bindDn, PASSWORDS.helpdesk1, 'a\\b\0c');
      const filter = readLog().slice(before).find((e) => e.op === 'search').filter;
      assert.ok(filter.includes('\\5c') && filter.includes('\\00'));
    });

    it('looks up one user by sAMAccountName, UPN or DN, and returns null for no match', async () => {
      const dn = `CN=Normal User,OU=Users,${CONTOSO}`;
      for (const id of ['normal.user', 'normal.user@contoso.test', dn]) {
        const u = await ldap.getUserByIdentifier(contoso(), bindDn, PASSWORDS.helpdesk1, id);
        assert.equal(u.dn, dn, `identifier ${id}`);
      }
      assert.equal(await ldap.getUserByIdentifier(contoso(), bindDn, PASSWORDS.helpdesk1, 'nobody'), null);
    });

    it('fails when the acting user supplies a bad password', async () => {
      await assert.rejects(ldap.searchUsers(contoso(), bindDn, 'wrong', 'abc'));
    });
  });

  describe('unlockUser / resetPassword (performed AS the signed-in user)', () => {
    const helpdesk = `CN=Help Desk One,OU=Users,${CONTOSO}`;
    const readonly = `CN=Read Only,OU=Users,${CONTOSO}`;
    const lockedDn = `CN=Locked User,OU=Users,${CONTOSO}`;
    const normalDn = `CN=Normal User,OU=Users,${CONTOSO}`;

    it('unlock writes lockoutTime=0 using the actor\'s own identity', async () => {
      const before = readLog().length;
      await ldap.unlockUser(contoso(), helpdesk, PASSWORDS.helpdesk1, lockedDn);
      const mod = readLog().slice(before).find((e) => e.op === 'modify');
      assert.equal(mod.by, helpdesk);
      assert.equal(mod.dn, lockedDn);
      assert.equal(mod.attr, 'lockoutTime');
      assert.deepEqual(mod.values, ['0']);
      assert.equal(mod.ok, true);
      const after = await ldap.getUserByIdentifier(contoso(), helpdesk, PASSWORDS.helpdesk1, 'locked.user');
      assert.equal(after.locked, false);
    });

    it('is refused by the directory when the actor lacks delegated rights', async () => {
      await assert.rejects(
        ldap.unlockUser(contoso(), readonly, PASSWORDS.readonly1, normalDn),
        (e) => e.name === 'InsufficientAccessRightsError'
      );
    });

    it('reset encodes the password as quoted UTF-16LE for unicodePwd', async () => {
      const before = readLog().length;
      await ldap.resetPassword(contoso(), helpdesk, PASSWORDS.helpdesk1, normalDn, 'N3w-Pässword!', false);
      const mods = readLog().slice(before).filter((e) => e.op === 'modify');
      assert.equal(mods.length, 1);
      assert.equal(mods[0].attr, 'unicodePwd');
      const decoded = Buffer.from(mods[0].values[0].base64, 'base64').toString('utf16le');
      assert.equal(decoded, '"N3w-Pässword!"');
    });

    it('forceChangeAtLogon additionally sets pwdLastSet=0', async () => {
      const before = readLog().length;
      await ldap.resetPassword(contoso(), helpdesk, PASSWORDS.helpdesk1, normalDn, 'An0ther-Pass!', true);
      const attrs = readLog().slice(before).filter((e) => e.op === 'modify').map((e) => e.attr);
      assert.deepEqual(attrs, ['unicodePwd', 'pwdLastSet']);
    });

    it('refuses to reset over a non-LDAPS connection (password would travel in clear)', async () => {
      const d = { ...contoso(), ldap_urls: ['ldap://dc1.contoso.test:389'] };
      const before = readLog().length;
      await assert.rejects(ldap.resetPassword(d, helpdesk, PASSWORDS.helpdesk1, normalDn, 'Whatever-123', false), /LDAPS/);
      assert.equal(readLog().slice(before).filter((e) => e.op === 'connect').length, 0, 'must not even connect');
    });

    it('refuses when ANY configured server is plain ldap://', async () => {
      const d = { ...contoso(), ldap_urls: ['ldaps://dc1.contoso.test:636', 'ldap://dc2.contoso.test:389'] };
      await assert.rejects(ldap.resetPassword(d, helpdesk, PASSWORDS.helpdesk1, normalDn, 'Whatever-123', false), /LDAPS/);
    });
  });

  describe('testServers (credential-free reachability check)', () => {
    it('reports an invalid URL without throwing', async () => {
      const [r] = await ldap.testServers(['not a url'], true);
      assert.equal(r.ok, false);
      assert.equal(r.error, 'Invalid URL');
    });

    it('reports success for a listening plain-TCP port and failure for a closed one', async () => {
      const net = require('net');
      const srv = net.createServer((s) => s.end());
      await new Promise((r) => srv.listen(0, '127.0.0.1', r));
      const open = srv.address().port;
      const closedProbe = net.createServer();
      await new Promise((r) => closedProbe.listen(0, '127.0.0.1', r));
      const closed = closedProbe.address().port;
      await new Promise((r) => closedProbe.close(r));
      const results = await ldap.testServers([`ldap://127.0.0.1:${open}`, `ldap://127.0.0.1:${closed}`], true);
      await new Promise((r) => srv.close(r));
      assert.equal(results[0].ok, true);
      assert.equal(results[1].ok, false);
    });

    it('returns an empty list for no servers', async () => {
      assert.deepEqual(await ldap.testServers([], true), []);
      assert.deepEqual(await ldap.testServers(undefined, true), []);
    });
  });
});
