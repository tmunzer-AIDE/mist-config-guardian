# Invitation email delivery

Status: approved for planning
Date: 2026-09-11

## Problem

An invited user cannot activate their account in any environment.

Three independent gaps produce this:

1. **No mail transport exists.** There is no SMTP client, configuration, or
   dependency anywhere in the backend. `UserInviteResponse.delivery` is
   hardcoded to the string `"not_implemented"` and nothing overrides it. The
   frontend's "Send invitation" button therefore promises something that never
   happens.
2. **Production withholds the only credential.** `_invitation_response` in
   `api/routes/users.py` returns `invitation_token` only when
   `settings.environment != "production"`, on the assumption that mail would
   carry it. `resend-invitation` returns through the same helper, so it
   withholds too, and no administrator route can set a password. The Helm
   chart defaults to `environment: production`. A Helm-deployed instance
   therefore creates `INVITED` accounts whose activation token is generated,
   hashed, stored, and then discarded unread.
3. **No page accepts an invitation.** `POST /api/v1/users/accept-invitation`
   exists and works, but the frontend has no route for it and never calls it.
   The wildcard route redirects any hand-built URL to the dashboard, which
   bounces to login.

Gap 3 means gaps 1 and 2 are not the whole story: even a development
deployment, which does return the token, has nowhere to spend it.

## Scope

This spec covers an SMTP transport and the invitation emails that use it. It
deliberately excludes the rest of product specification §11 — notification
policies, `NotificationDelivery` with queued retry and backoff, Slack, and
Teams. Those are Phase 5 and are separate sub-projects. They will reuse the
transport built here; nothing in this design should assume they exist.

Out of scope, filed separately: the Helm configmap does not set
`WEBAUTHN_ORIGIN` or `WEBAUTHN_RP_ID`, so a Helm-deployed instance keeps the
localhost defaults and passkeys cannot work. That bug is why this design does
not derive the public URL from `webauthn_origin`.

## The delivery invariant

Everything else follows from one rule:

> The invitation token is returned in the API response **if and only if**
> email did not carry it.

`environment` stops being a factor and the production special case is deleted.
An invitation is then never simultaneously undelivered and unreachable, which
is the defect in gap 2. The administrator is given a token to pass on by hand
exactly when the system failed to deliver one itself.

`UserInviteResponse.delivery` becomes an enum replacing the hardcoded string:

| Value | Meaning | Token returned |
|---|---|---|
| `sent` | The mail server accepted the message | No |
| `not_configured` | SMTP is not enabled | Yes |
| `failed` | SMTP is enabled but the send raised | Yes |

Creating the user always succeeds. A broken mail server degrades invitation
delivery; it never blocks onboarding.

## Design

### SMTP configuration

Admin-editable runtime configuration on the existing `ApplicationConfiguration`
singleton, mirroring the Impact AI settings field for field — the same
`encrypted_*` plus `*_last_four` treatment for the secret, and the same
`*_last_test_at` / `*_last_test_ok` / `*_last_test_detail` triple driving a
test-connection button.

New fields:

| Field | Type | Notes |
|---|---|---|
| `smtp_enabled` | `bool` | Default `False` |
| `smtp_host` | `str` | |
| `smtp_port` | `int` | Default 587 |
| `smtp_security` | `Literal["starttls", "tls", "none"]` | Default `starttls` |
| `smtp_username` | `str` | Empty means unauthenticated |
| `encrypted_smtp_password` | `str \| None` | Vault, per §16 |
| `smtp_password_last_four` | `str \| None` | Display only |
| `smtp_from_address` | `str` | |
| `smtp_from_name` | `str` | |
| `smtp_last_test_at` | `datetime \| None` | |
| `smtp_last_test_ok` | `bool \| None` | |
| `smtp_last_test_detail` | `str \| None` | |

Endpoints follow the AI settings precedent: read, update, and a test-connection
POST that sends nothing and only proves the server can be reached and
authenticated against.

`smtp_enabled` may not be set true without a host and a from address; the
service rejects the update, exactly as the AI settings reject being enabled
without an API key.

### Public base URL

An email needs an absolute link, and the application currently has no notion of
its own public address: `deep_link` builds query parameters only, because the
browser supplies its own origin.

`Settings` gains a `public_base_url` property derived from
`parsed_cors_origins[0]`, with an optional `PUBLIC_BASE_URL` environment
override.

Deriving rather than adding a required setting is deliberate. A CORS origin is
self-validating: if it is wrong, the browser application cannot call the API at
all, so it is necessarily correct in any working deployment. It is already
wired through the Helm configmap and `.env.example`. Adding a new required
setting would introduce a value that can be silently wrong, and a production
guard to catch that, for no gain in the common case.

The override exists for the one case the derivation cannot resolve: a
deployment listing several origins, where "first" is arbitrary. The development
default lists two.

The Host header is not used. It is attacker-controlled, and §16 requires not
trusting arbitrary forwarded headers; an activation link built from it would be
spoofable by anyone who can reach the API.

If `parsed_cors_origins` is empty and no override is set, `public_base_url` is
`None`, and enabling SMTP is rejected with an error naming the missing setting.

### Transport

A new `integrations/smtp.py`, beside `integrations/mist_config.py`.

Standard-library `smtplib` run through `asyncio.to_thread`, with a connect and
send timeout. No new dependency: one inline send per invitation does not
justify `aiosmtplib`, and the blocking client is kept off the event loop by the
thread.

The sender sits behind a `MailSender` Protocol, matching how `NotificationStore`,
`ChangeGroupStore`, and `AiProviderFactory` are already structured, so tests
inject a fake and no test touches a network.

`smtp_security` maps to: `starttls` — connect plain, then `STARTTLS`; `tls` —
connect wrapped (`SMTP_SSL`); `none` — connect plain, no upgrade. Authentication
is attempted only when a username is set.

### Sending

Sending is inline, within the invite request, because the delivery invariant
requires the response to know whether the message was accepted. Failures are
caught and converted to the `failed` outcome; they never propagate as an HTTP
error, and never prevent the account being created.

The product specification's "queued, retried with backoff" describes the
notification channels — high-volume, background, no user waiting. An invitation
is low-volume, interactive, and user-initiated, and the administrator wants to
know now whether to copy a link. When the Phase 5 delivery queue is built it
will reuse this transport; this path does not need it.

### Email content

Plain text with a minimal HTML alternative. States who invited the recipient,
the application name, the activation link, and the expiry (7 days, from
`INVITATION_LIFETIME_DAYS`).

The token appears only inside the activation URL. Per §16 it is never logged:
log records carry the recipient, the outcome, and the SMTP server's response
code, and nothing else.

### Accept-invitation page

A new unauthenticated frontend route `accept-invitation`, reading the token
from `?token=`, taking a password and a confirmation, posting to the existing
endpoint, and redirecting to login on success.

It must sit outside the authentication guard and before the wildcard route,
which currently swallows it. Invalid, expired, and already-accepted tokens all
surface the endpoint's single deliberately indistinct message rather than
revealing which.

`SETTINGS_TABS` in `services/deep_links.py` gains `"email"` for the new
settings tab. `deep_link` validates against that frozenset and raises for a tab
it does not know, so omitting this breaks any deep link to the tab.

### Resend throttling

`resend-invitation` currently has no rate limit. With mail wired up it becomes
an outbound-email trigger that any administrator can hammer, which is both a
spam vector and a way to burn a mail provider's reputation.

The existing `services/throttling.py` — which already counts sign-in failures
per account and per address in a fixed window — is to be reused if its shape
fits. If it does not, resend is limited to one send per user per minute with a
counter in the same style, rather than left unlimited.

## Testing

- The invariant, driven directly with a fake `MailSender`: accepted send
  returns no token and `sent`; disabled SMTP returns the token and
  `not_configured`; a sender that raises returns the token and `failed`.
- Production is no longer special: the same three cases assert identically with
  `environment="production"`.
- `public_base_url` derivation: single origin, multiple origins, explicit
  override, none configured.
- Activation link construction, and that the token appears in no log record.
- Enabling SMTP without a host, without a from address, and without a
  resolvable public base URL is rejected.
- `smtp_security` selects the right client and upgrade path.
- The test-connection endpoint records its outcome to the `smtp_last_test_*`
  fields and sends no message.
- The accept-invitation page: valid token activates and redirects; invalid and
  expired tokens show the indistinct failure; mismatched confirmation is
  refused client-side.
- Resend throttling refuses the second send inside the window.

No test performs real network I/O.

## Consequences

The API contract changes: `UserInviteResponse.delivery` becomes an enum, and
`invitation_token` is populated under a new condition. `docs/openapi.json` must
be regenerated, since `make check` compares it.

Existing `INVITED` accounts stranded by the current behaviour are not migrated.
Once this ships, an administrator resends the invitation and the token is
returned or delivered. This is deliberate: minting new tokens for existing
accounts without an administrator asking would be a security change, not a fix.
