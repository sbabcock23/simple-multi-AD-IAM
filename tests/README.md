# Automated tests

~390 tests, **no external services needed**: no Active Directory, Duo account or mail server.
Uses only Node's built-in test runner (`node:test`) - nothing new to install. Node >= 20.

```bash
npm install
npm test                  # everything (~25 s)
npm run test:unit         # in-process module tests (~2 s)
npm run test:integration  # boots the real server.js and drives it over HTTP
node tests/run.js integration "unlock"   # only tests whose name matches "unlock"
```

CI: `.github/workflows/ci.yml` runs the same commands on Node 20 and 22, then builds the Docker
image and smoke-tests the running container.

## How it works

| Layer | What runs for real | What is faked |
|---|---|---|
| `tests/unit/*` | `src/*.js` modules, SQLite database, crypto, JWT | `ldapjs` (only in `ldap.test.js`) |
| `tests/integration/*` | **the real `server.js`** as a child process (user + admin ports), real Express stack, real SQLite file in a temp dir, real `nodemailer` | `ldapjs` and the Duo SDK, via a `node -r` preload |

* `helpers/fakeServices.preload.js` replaces `ldapjs` / `@duosecurity/duo_universal` with in-memory
  fakes. The app's own `src/ldap.js` and `src/duo.js` still run, so LDAP filter building, nested-group
  authorisation, server failover, `unicodePwd` encoding, the Duo state check, etc. are all exercised.
* `helpers/directory.js` is the fake directory: two domains, nested groups, locked/disabled accounts,
  a user without delegated rights, an e-mail address that differs from the UPN, a down server.
* `helpers/fakeSmtp.js` is a tiny SMTP sink so alert e-mails can be asserted on.
* Every integration file starts its own server on random ports in a fresh data directory, so files
  are independent and run in parallel. The app source is never modified.

## What is covered

* **Sign-in**: UPN / e-mail (lookup account) / NetBIOS fallback, allowed-group + nested-group
  authorisation, fail-closed behaviour, locked/disabled accounts, one generic error message,
  LDAP-filter and SQL injection, forged / expired / unsigned / wrong-role tokens, sliding sessions.
* **Directory actions**: search, unlock, reset password (UTF-16LE encoding, force-change, LDAPS-only),
  per-domain feature switches, actions executed as the signed-in user, delegated-rights failures.
* **Duo MFA**: no session before MFA, state/CSRF checks, denied/forged codes, replay, per-domain
  overrides, fail-closed when misconfigured, secrets never exposed.
* **Admin API**: authentication on every endpoint, domain CRUD + validation, write-only secrets,
  admins, session timeouts, retention, templates, reports, CSV export.
* **Alerts**: global/domain switches, recipients and SMTP overrides, templates, no secrets in mail,
  SMTP outage never affects users.
* **Operations**: port isolation, security headers, cookie flags, rate limiting, restart persistence,
  JWT / encryption-key rotation, in-place schema migration, no secrets in logs, resilience to junk input.

## Known gaps ("findings")

Tests marked `todo` assert the **safe** behaviour for weaknesses found in the app. They do not fail
the build, are listed in the run summary, and start reporting "now PASS" once the app is fixed - at
that point delete the `todo` option. Current list: server-side logout / revoked-admin sessions,
spoofable `X-Forwarded-For` in audit records, silent fallback to the built-in JWT secret, replayable
MFA-pending cookie, `null` accepted as audit-retention 0, and a hanging request for non-string login
credentials. (Node's reporter prints these under "failing tests" - that is just how it lists `todo`.)

## Limits

The fakes implement only the slice of LDAP/Duo behaviour this app uses; they cannot prove
compatibility with a real domain controller or Duo tenant (TLS/certificates, AD error codes, replication
delay). Keep a manual pre-release check against a test AD. The browser UI is only checked statically
(valid JS, referenced assets exist, no inline scripts) - there are no browser tests.

## Adding tests

Copy a file from `tests/integration/`, use `startApp()` from `helpers/app.js`, `createDomain()` /
`auditRows()` from `helpers/util.js`, and extend `helpers/directory.js` if you need more accounts.
