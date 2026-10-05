'use strict';
/** Fixture for the fake Active Directory (see fakeServices.preload.js). */

const CONTOSO = 'DC=contoso,DC=test';
const FABRIKAM = 'DC=fabrikam,DC=test';

const PASSWORDS = {
  helpdesk1: 'Helpd3sk!Pass',
  nested1: 'N3sted!Pass',
  legacy1: 'L3gacy!Pass',
  readonly1: 'R3adonly!Pass',
  outsider1: 'Outs1der!Pass',
  amy: 'Amy!Passw0rd',
  lookup: 'L00kup!Pass',
};

function dnToSuffix(base) {
  return base.replace(/DC=/g, '').replace(/,/g, '.');
}

function user(base, netbios, sam, extra = {}) {
  const display = extra.displayName || sam;
  return {
    dn: `CN=${display},OU=Users,${base}`,
    sAMAccountName: sam,
    cn: display,
    displayName: display,
    userPrincipalName: `${sam}@${dnToSuffix(base)}`,
    mail: `${sam}@${dnToSuffix(base)}`,
    netbios,
    lockoutTime: '0',
    userAccountControl: '512',
    memberOf: [],
    delegated: false,
    ...extra,
  };
}

function buildDirectory(overrides = {}) {
  const helpdeskDn = `CN=Helpdesk,OU=Groups,${CONTOSO}`;
  const l1Dn = `CN=Helpdesk-L1,OU=Groups,${CONTOSO}`;
  const supportDn = `CN=Support,OU=Groups,${FABRIKAM}`;
  return {
    downUrls: ['ldaps://dead.contoso.test:636'],
    groups: [
      { dn: helpdeskDn, cn: 'Helpdesk', memberOf: [] },
      // Helpdesk-L1 is nested INSIDE Helpdesk: its members must be authorised via the chain.
      { dn: l1Dn, cn: 'Helpdesk-L1', memberOf: [helpdeskDn] },
      { dn: `CN=Domain Admins,CN=Users,${CONTOSO}`, cn: 'Domain Admins', memberOf: [] },
      { dn: supportDn, cn: 'Support', memberOf: [] },
    ],
    users: [
      user(CONTOSO, 'CONTOSO', 'helpdesk1', {
        displayName: 'Help Desk One', mail: 'helpdesk1@contoso.com',
        password: PASSWORDS.helpdesk1, memberOf: [helpdeskDn], delegated: true,
      }),
      user(CONTOSO, 'CONTOSO', 'nested1', { displayName: 'Nested Helper', password: PASSWORDS.nested1, memberOf: [l1Dn], delegated: true }),
      // UPN differs from what the person types -> exercises the NetBIOS fallback.
      user(CONTOSO, 'CONTOSO', 'legacy1', {
        displayName: 'Legacy User', userPrincipalName: 'legacy1@corp.contoso.local', mail: 'legacy1@corp.contoso.local',
        password: PASSWORDS.legacy1, memberOf: [helpdeskDn], delegated: true,
      }),
      // In the allowed group but WITHOUT delegated AD rights.
      user(CONTOSO, 'CONTOSO', 'readonly1', { displayName: 'Read Only', password: PASSWORDS.readonly1, memberOf: [helpdeskDn], delegated: false }),
      // Valid credentials but not in any allowed group.
      user(CONTOSO, 'CONTOSO', 'outsider1', { displayName: 'Outsider', password: PASSWORDS.outsider1 }),
      // Targets for unlock / reset.
      user(CONTOSO, 'CONTOSO', 'locked.user', { displayName: 'Locked User', password: 'Whatever1!', lockoutTime: '133500000000000000' }),
      user(CONTOSO, 'CONTOSO', 'normal.user', { displayName: 'Normal User', password: 'Whatever2!' }),
      user(CONTOSO, 'CONTOSO', 'disabled.user', { displayName: 'Disabled User', password: 'Whatever3!', userAccountControl: '514' }),
      // Fabrikam: login by e-mail address whose domain differs from the UPN suffix.
      user(FABRIKAM, 'FABRIKAM', 'amy', {
        displayName: 'Amy Support', userPrincipalName: 'amy@corp.fabrikam.local', mail: 'amy@fabrikam.com',
        password: PASSWORDS.amy, memberOf: [supportDn], delegated: true,
      }),
      user(FABRIKAM, 'FABRIKAM', 'svc-lookup', {
        dn: `CN=svc-lookup,OU=Service,${FABRIKAM}`, displayName: 'svc-lookup', password: PASSWORDS.lookup, mail: undefined,
      }),
      user(FABRIKAM, 'FABRIKAM', 'bob.f', { displayName: 'Bob Fabrikam', password: 'Whatever4!', lockoutTime: '133500000000000001' }),
    ],
    ...overrides,
  };
}

const contosoDomain = (over = {}) => ({
  name: 'Contoso',
  domain_suffix: 'contoso.test',
  ldap_urls: ['ldaps://dc1.contoso.test:636', 'ldaps://dc2.contoso.test:636'],
  base_dn: CONTOSO,
  netbios_name: 'CONTOSO',
  allowed_groups: ['Helpdesk'],
  tls_reject_unauthorized: false,
  ...over,
});

const fabrikamDomain = (over = {}) => ({
  name: 'Fabrikam',
  domain_suffix: 'fabrikam.com',
  ldap_urls: ['ldaps://dc1.fabrikam.test:636'],
  base_dn: FABRIKAM,
  netbios_name: 'FABRIKAM',
  allowed_groups: ['Support'],
  lookup_bind_dn: `CN=svc-lookup,OU=Service,${FABRIKAM}`,
  lookup_bind_password: PASSWORDS.lookup,
  tls_reject_unauthorized: false,
  ...over,
});

module.exports = { buildDirectory, contosoDomain, fabrikamDomain, PASSWORDS, CONTOSO, FABRIKAM };
