'use strict';
const { describe, it, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const { setupUnitEnv } = require('../helpers/env');

const env = setupUnitEnv();
const db = require('../../src/db');
const domains = require('../../src/domains');

function insert(over = {}) {
  const now = new Date().toISOString();
  const row = {
    name: 'D', domain_suffix: 'd.test', ldap_urls: '["ldaps://a:636"]', base_dn: 'DC=d,DC=test',
    allowed_groups: '["Helpdesk"]', alert_config: '{}', duo_config: '{}', enabled: 1, ...over,
  };
  return db.prepare(`INSERT INTO domains (name, domain_suffix, ldap_urls, base_dn, allowed_groups, alert_config, duo_config, enabled, created_at, updated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?)`).run(row.name, row.domain_suffix, row.ldap_urls, row.base_dn, row.allowed_groups, row.alert_config, row.duo_config, row.enabled, now, now).lastInsertRowid;
}

describe('src/domains', () => {
  beforeEach(() => db.prepare('DELETE FROM domains').run());
  after(() => env.cleanup());

  it('parses JSON columns into real arrays/objects', () => {
    const id = insert({ alert_config: '{"enabled":false}', duo_config: '{"mode":"enforced"}' });
    const d = domains.getById(id);
    assert.deepEqual(d.ldap_urls, ['ldaps://a:636']);
    assert.deepEqual(d.allowed_groups, ['Helpdesk']);
    assert.equal(d.alert_config.enabled, false);
    assert.equal(d.duo_config.mode, 'enforced');
  });

  it('falls back safely when stored JSON is corrupt or the wrong shape', () => {
    const id = insert({ ldap_urls: 'not json', allowed_groups: '{"a":1}', alert_config: '[]', duo_config: 'x' });
    const d = domains.getById(id);
    assert.deepEqual(d.ldap_urls, []);
    assert.deepEqual(d.allowed_groups, ['Domain Admins'], 'default allowed group');
    assert.deepEqual(d.alert_config, {});
    assert.deepEqual(d.duo_config, {});
  });

  it('getById returns undefined for a missing domain', () => {
    assert.equal(domains.getById(9999), undefined);
  });

  it('getBySuffix only returns ENABLED domains (disabled domains cannot be signed in to)', () => {
    insert({ domain_suffix: 'on.test' });
    insert({ domain_suffix: 'off.test', enabled: 0 });
    assert.ok(domains.getBySuffix('on.test'));
    assert.equal(domains.getBySuffix('off.test'), undefined);
    assert.equal(domains.getBySuffix('nope.test'), undefined);
  });

  it('suffix lookup is exact (no partial/suffix matching)', () => {
    insert({ domain_suffix: 'corp.example.test' });
    assert.equal(domains.getBySuffix('example.test'), undefined);
    assert.equal(domains.getBySuffix('evil-corp.example.test'), undefined);
  });

  it('listAll is ordered by name', () => {
    insert({ name: 'Zeta', domain_suffix: 'z.test' });
    insert({ name: 'Alpha', domain_suffix: 'a.test' });
    assert.deepEqual(domains.listAll().map((d) => d.name), ['Alpha', 'Zeta']);
  });
});
