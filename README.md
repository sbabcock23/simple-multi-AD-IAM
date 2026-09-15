# IAM Self-Service (multi-domain AD unlock & password reset)

A small self-service web app for unlocking Active Directory accounts and
resetting passwords across **multiple AD domains/forests**, deployable as a
single Docker container.

## How it works

- **Admins** log in to `/admin` with a local username/password (stored in a
  local SQLite database, not AD) and configure one or more AD **domains**:
  a display name, the email suffix used to route logins (e.g. `contoso.com`),
  one or more LDAP server URLs, the search base DN, and which self-service
  **features** (unlock, reset password, force change at next logon) and
  **audit logging** are enabled for that domain.
- **End users** (e.g. helpdesk/support staff) log in at `/` with
  `username@domain.com`. The part after `@` is matched against a configured
  domain's suffix, and the app authenticates the credentials directly
  against that domain's AD via an LDAP bind.
- **There is no stored service account.** Every directory operation —
  search, unlock, or password reset — is performed using the signed-in
  user's *own* AD credentials, cached only inside their encrypted, signed,
  httpOnly session cookie for the duration of their session. This means
  the AD account of anyone using this portal must itself have the
  delegated permissions described below.
- Once signed in, the user searches for a target AD account (or types an
  exact sAMAccountName/UPN) and can **unlock** it or **reset its password**,
  provided their domain has that feature enabled. Feature buttons are only
  shown if the admin has enabled them for the matching domain — the server
  also re-checks the flag before executing, so it's not just a UI hide.
- **Multiple LDAP servers per domain** are supported for failover (e.g. two
  domain controllers) — add as many as you like in the domain form.

## Audit logging

- A **global switch** (Admin → Audit settings) turns all logging on or off.
- Each **domain** also has its own audit toggle, which only matters while
  logging is globally on — so you can exclude a specific domain even while
  auditing everything else.
- Logged events: `login`, `logout`, `search`, `unlock`, `reset_password` —
  each records **who** (the signed-in actor), **when** (timestamp), **where**
  (client IP address), **what target** (searched query or acted-upon
  account), and **whether it succeeded**, with a detail message on failure.
- Failed logins are logged even when the domain suffix doesn't match any
  configured domain (shown as "Unmatched domain attempts" in the admin
  filter), subject only to the global switch since there's no per-domain
  setting to consult in that case.
- **Admin → Audit log**: filter by domain, event type, and success/failure,
  and **download the filtered results as a CSV file**.
- **User portal → My activity**: each signed-in user sees their own login
  and action history (current session and past), but never other users'.

## Required Active Directory setup

For each domain you add:

1. **No service account is needed or stored.** Each person who uses this
   portal signs in with, and the app acts as, their own AD account.
2. Every AD account that will use this portal (e.g. your helpdesk team)
   needs **delegated permissions** on the OUs containing the accounts they
   should be able to manage:
   - `Reset Password`
   - `Read lockoutTime` / `Write lockoutTime` (unlock uses this attribute)
   - `Write pwdLastSet` (only needed if "force change at next logon" is used)
   - You can grant these via the **Delegation of Control Wizard** in AD
     Users and Computers — no Domain Admin rights required. Directory
     *searching* generally works with default Authenticated Users read
     access; only unlock/reset need the extra delegation above.
3. **LDAPS (`ldaps://`, typically port 636) on every configured server for
   the domain** is required for password resets, because AD only accepts
   writes to `unicodePwd` over an encrypted connection. Plain `ldap://` can
   be used if only unlock is enabled for that domain, but LDAPS everywhere
   is recommended.
4. A **Base DN** to scope searches, e.g. `DC=contoso,DC=com`, or an OU-scoped
   DN such as `OU=Employees,DC=contoso,DC=com`.
5. Add **one or more LDAP server URLs** (e.g. your domain controllers) for
   failover — use **Test connection** in the admin UI to verify each server
   is reachable before saving. This is a network reachability check only
   (no credentials involved), since the app has no stored login to test with.

## Running with Docker Compose

```bash
cp .env.example .env
# edit .env: set JWT_SECRET, ENCRYPTION_KEY, and the bootstrap admin password

docker compose up -d --build
```

The app will be available at `http://localhost:3000`. Sign in to `/admin`
with the bootstrap admin account (from `.env`), change its password, and
add your domains.

Configuration (domains, admin users, audit log) is stored in a SQLite
database inside the named `iam-data` volume, so it persists across
container restarts.

## Running with plain Docker

```bash
docker build -t iam-self-service .
docker run -d \
  -p 3000:3000 \
  -e JWT_SECRET="$(openssl rand -hex 32)" \
  -e ENCRYPTION_KEY="$(openssl rand -hex 32)" \
  -e ADMIN_BOOTSTRAP_USER=admin \
  -e ADMIN_BOOTSTRAP_PASSWORD="a-strong-temporary-password" \
  -v iam-data:/app/data \
  --name iam-self-service \
  iam-self-service
```

## Environment variables

| Variable | Purpose |
|---|---|
| `JWT_SECRET` | Signs session cookies. Set a long random value in production. |
| `ENCRYPTION_KEY` | Encrypts the end user's own password inside their session cookie (needed to perform directory operations as them) and, for older deployments, any legacy stored bind password. Set a long random value. |
| `ADMIN_BOOTSTRAP_USER` / `ADMIN_BOOTSTRAP_PASSWORD` | Creates the first local admin account on first run only. Change the password after first login. |
| `COOKIE_SECURE` | Set to `true` once the app is served over HTTPS, so session cookies are marked `Secure`. |
| `TRUST_PROXY` | Number of reverse proxy hops in front of this app (e.g. `1` for a single nginx/Traefik/PaaS router). Leave unset if the app is reached directly. See "Running behind a reverse proxy" below. |
| `LOG_LEVEL` | Console log verbosity: `error`, `warn`, `info` (default), `debug`, or `silent`. See "Logging" below. |
| `PORT` | Port the app listens on (default `3000`). |
| `DATA_DIR` | Where the SQLite database file is stored (default `/app/data` in the container). |

## Logging

Every request and every notable server-side event is logged to stdout in a
structured, grep-friendly format — this is what `docker compose logs -f
iam-app` (or `docker logs -f <container>`) shows:

```
2026-09-14T11:12:31.564Z [INFO] admin_login_success requestId=b4995b2c9a6d username=admin ip=127.0.0.1
2026-09-14T11:12:31.567Z [INFO] request requestId=b4995b2c9a6d method=POST path=/api/admin/login status=200 durationMs=4 ip=127.0.0.1
2026-09-14T11:34:02.118Z [WARN] user_login_failed requestId=a1c9f0e2 username=jdoe@contoso.com domain=Contoso reason=ldap_bind_failed error="InvalidCredentialsError" ip=10.0.0.5
```

- **Every response carries an `X-Request-Id` header**, and every error the
  server sends back includes the same ID in its JSON body (the frontend
  also appends it to the error text shown on screen, e.g. `"... (ref:
  a1c9f0e2)"`). If something fails, you can go straight to
  `docker compose logs iam-app | grep a1c9f0e2` and see exactly what
  happened for that request — including the real LDAP error (wrong
  password vs. server unreachable vs. TLS/certificate failure vs. wrong
  Base DN), which is never shown to the end user but always logged
  server-side.
- **`LOG_LEVEL`** controls verbosity: `error`/`warn`/`info` (default) cover
  normal operation and failures; `debug` additionally logs individual LDAP
  bind/search/modify attempts (usernames and DNs, never passwords) — useful
  when troubleshooting a domain that won't connect. `silent` disables
  logging entirely.
- **Any error your browser sees is guaranteed to be JSON**, never an HTML
  error page. A catch-all error handler on the server ensures this even for
  bugs that weren't anticipated by a specific route's own error handling,
  and every such case is logged server-side with a full stack trace.
- **LDAP connection errors can't silently crash the app.** Each LDAP client
  now has an explicit error listener; without one, a dropped connection or
  unreachable server can crash the entire Node process (a Node.js
  EventEmitter behavior, not specific to this app) rather than just failing
  the one request that hit it. Errors are logged as `ldap_client_error` /
  `ldap_connect_error` instead.
- If the process does hit something truly unexpected outside of normal
  request handling, it logs `uncaught_exception` with the full error and
  exits — Docker's `restart: unless-stopped` policy then brings up a clean
  instance rather than the app limping along in a bad state. Check the logs
  immediately after a restart if this happens; that log line tells you
  exactly what happened.

## Running behind a reverse proxy

If you put this app behind nginx, Traefik, a cloud load balancer, or any
PaaS router, that proxy will add an `X-Forwarded-For` header. Set
`TRUST_PROXY` to the number of proxy hops in front of the app (usually `1`)
so Express can resolve the real client IP correctly — this is what the
audit log's "where" column uses, and it's also required by the login
rate limiter. If you don't set it, login still works (the app is hardened
against the common `ERR_ERL_UNEXPECTED_X_FORWARDED_FOR` failure mode either
way), but the audit log may show your proxy's address instead of the
actual client IP.

## Security notes

- Put this application behind HTTPS/TLS (a reverse proxy such as nginx,
  Traefik, or a load balancer) in any real deployment, and set
  `COOKIE_SECURE=true` once you do.
- The end user's AD password is kept only inside their own encrypted,
  signed, httpOnly session cookie for up to 2 hours, and is never written
  to disk or logged. Protect `ENCRYPTION_KEY` and `JWT_SECRET` the same way
  you'd protect any credential-bearing secret (e.g. via your orchestrator's
  secret store rather than committing them to source control).
- Login and admin-login endpoints are rate-limited to slow down brute-force
  attempts, but you should still enforce AD account lockout policy and
  review the audit log for repeated failures.
- Since every user's own AD permissions govern what they can do, scope
  delegated `Reset Password`/`lockoutTime` rights only to the OUs and staff
  who should have self-service helpdesk access.
- Consider placing this app on an internal network or behind SSO/VPN.
- Sessions are stateless (all the info needed lives in the signed cookie),
  so the app can be deployed as multiple replicas without a shared session
  store — as long as they share the same `JWT_SECRET`/`ENCRYPTION_KEY` and
  the same SQLite data volume (or you move config storage to a shared DB).

## Upgrading from an earlier version of this app

Earlier builds stored a single LDAP URL plus a service-account bind DN and
password per domain. On startup, this version automatically adds the new
`ldap_urls` (multi-server) and `audit_enabled` columns to existing domains
and migrates any old `ldap_url` value into the new `ldap_urls` list, so
existing domains keep working without manual SQL. The old bind DN/password
columns are simply no longer read — you can leave them in place or remove
them at your convenience. After upgrading, anyone using the portal will
need their **own** AD account to have the delegated permissions described
above, since there's no longer a shared service account performing the
directory writes.

## Project structure

```
server.js                  Express app entrypoint
src/db.js                  SQLite schema, defaults, and migrations
src/domains.js             Reads domain config rows (parses ldap_urls JSON)
src/audit.js                Writes audit log entries, respecting global/per-domain toggles
src/crypto.js               AES-256-GCM encryption helpers
src/auth.js                Password hashing + JWT session helpers
src/middleware.js          Route guards; decrypts the cached AD password for user sessions
src/ldap.js                All LDAP/AD operations, bound as the signed-in user, with multi-server failover
src/routes/adminAuth.js    Admin login/logout
src/routes/adminApi.js     Domain, settings, audit log, and admin-user management API
src/routes/userAuth.js     End-user login (matches email domain -> AD domain) + audit logging
src/routes/userApi.js      End-user search/unlock/reset API + "my activity" audit feed
public/                    Static frontend (user portal + admin portal)
```
