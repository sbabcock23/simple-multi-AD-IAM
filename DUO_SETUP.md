# Setting up Cisco Duo MFA

This app integrates with Cisco Duo's **Universal Prompt** (the modern,
OAuth2-based Duo login experience) to add a second factor after a
successful Active Directory username/password sign-in on the **user
portal**. This guide walks through setting it up end to end.

MFA has exactly two modes: **Enforced** (required for every login) or
**Disabled**. There is no "optional" mode. You can set this globally and
optionally override it per domain — see "Global vs. per-domain" below.

---

## 1. Create a Duo application

1. Sign in to the [Duo Admin Panel](https://admin.duosecurity.com).
2. Go to **Applications → Protect an Application**.
3. Search for and select **"Duo Single Sign-On"** or, if your Duo edition
   exposes it directly, an application type described as **Generic
   OIDC Relying Party** / **Web SDK / Universal Prompt**. (The exact naming
   varies by Duo edition — what matters is that it's an OIDC-based
   Universal Prompt application, not a legacy "Duo Auth API (traditional
   prompt)" integration, which this app does not use.)
4. Give it a recognizable name, e.g. `IAM Self-Service Portal`.
5. Once created, note down three values from the application's details
   page — you'll need all three:
   - **Client ID**
   - **Client secret**
   - **API hostname** (looks like `api-XXXXXXXX.duosecurity.com`)

## 2. Set the redirect URL

Duo needs to know exactly where to send the browser back to after the
person completes (or cancels) the prompt. This app exposes that endpoint
at:

```
/api/auth/duo-callback
```

**This must point at the user portal's address, not the admin portal's.**
The user portal and admin portal listen on separate ports (`PORT`, default
`3000`, and `ADMIN_PORT`, default `3001`) — use the user portal's
host/port/scheme here. Examples:

| Deployment | Redirect URL to use |
|---|---|
| Behind a reverse proxy at `https://portal.contoso.com` | `https://portal.contoso.com/api/auth/duo-callback` |
| Direct access, no proxy, default port | `http://your-server:3000/api/auth/duo-callback` |

In the Duo application's settings, find the **Redirect URI(s)** field and
enter this exact URL. It must match **character-for-character** what you
enter in this app's admin portal in step 3 below — Duo rejects any
mismatch (including trailing slashes, `http` vs `https`, or a different
port).

## 3. Enter the details in the admin portal

1. Go to the **admin portal** (`ADMIN_PORT`, default `3001`) and sign in.
2. Find the **Multi-factor authentication (Cisco Duo)** card.
3. Fill in:
   - **Client ID**
   - **Client secret**
   - **API hostname**
   - **Redirect URL** — exactly what you registered in step 2
4. Leave **Mode** set to **Disabled** for now.
5. Click **Save settings**.
6. Click **Test Duo connection**. This performs a Duo health check (no
   password/2FA involved) and confirms the four values above are valid
   and Duo is reachable. Fix anything it reports before continuing.

## 4. Turn it on

Once the test succeeds:

- To enforce MFA for **everyone**, set **Mode** to **Enforced** and save.
- To enforce it for only **some domains**, leave the global mode
  **Disabled** and instead override it per domain (see below).

Do a live test login on the **user portal** with a real AD account before
rolling this out broadly — you should be redirected to Duo's hosted
prompt, and after approving it, land back in the portal fully signed in.

## Global vs. per-domain

Each domain (Admin → edit a domain → **Multi-factor authentication
override**) can independently set its **Mode** to:

- **Inherit global setting** (default) — follows whatever the global mode
  is set to.
- **Enforced** — MFA required for this domain regardless of the global
  setting.
- **Disabled** — MFA skipped for this domain regardless of the global
  setting.

A domain can also check **"Use a different Duo application for this
domain"** to use entirely separate Client ID/Secret/API hostname/Redirect
URL from the global ones — useful if different domains/business units have
their own Duo accounts. When checked, fill in and test all four fields the
same way as the global setup above (the domain's own **Test Duo
connection** button tests whichever set of credentials is actually in
effect — its own override if checked, otherwise the global ones).

## Fail-closed behavior

If a domain resolves to "enforced" (via its own setting or by inheriting
the global one) but the Duo application details aren't fully filled in,
**login is denied outright** with a clear error — it is never silently
downgraded to password-only. This is checked in two places: the admin
portal refuses to save "Enforced" without complete credentials in the
first place, and the login flow itself re-checks at sign-in time as a
backstop. Both cases are logged server-side as `duo_misconfigured`.

## Verifying it's working

- **Admin → Audit log**, filter by event type **"MFA challenge issued"** to
  see every time a Duo prompt was sent.
- **Admin → Reports → MFA activity** shows a per-user/per-domain summary:
  challenges sent, completed logins, and MFA failures.
- Server logs (`docker compose logs -f iam-app`, or wherever you're
  capturing stdout) contain `mfa_challenge_started`, `mfa_verify_failed`,
  `mfa_denied_by_duo`, and `duo_misconfigured` entries for troubleshooting.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| "Multi-factor authentication is required but not configured correctly" | Mode is enforced (globally or for that domain) but one of Client ID/Secret/API hostname/Redirect URL is blank or was never saved. |
| Duo shows an error page before you even see the prompt | The redirect URL registered in Duo doesn't exactly match what's saved in this app's admin portal — check scheme, host, port, and trailing slash. |
| Stuck on "Redirecting to Duo..." or a blank page after approving the prompt | The redirect URL points at the wrong port (admin port instead of user portal port) or a host the browser can't reach — confirm it's the user portal's own externally-reachable address. |
| "Multi-factor authentication failed or was cancelled. Please sign in again." | Either the person actually cancelled/denied the Duo prompt, or too much time passed (the pending sign-in state expires after 5 minutes) — check the audit log for the specific reason. |
| Test Duo connection fails | Usually an incorrect API hostname or a firewall/proxy blocking outbound HTTPS from this server to `*.duosecurity.com`. |

## Security notes

- The Duo Client Secret (and any per-domain override secret) is encrypted
  at rest using the same mechanism as this app's other stored credentials
  — see the main [README](README.md#security-notes) for details on
  `ENCRYPTION_KEY`.
- The brief window between redirecting to Duo and the person completing
  the prompt is tracked with a short-lived (5 minute), signed, httpOnly
  cookie that is entirely separate from the real session cookie — a full
  session is never issued until Duo confirms the second factor.
