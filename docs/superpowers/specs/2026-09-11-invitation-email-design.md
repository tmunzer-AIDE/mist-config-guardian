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

## The delivery rule

Everything else follows from one rule, stated in one direction only:

> The invitation credential is returned in the API response **unless positive
> SMTP acceptance was observed**.

`environment` stops being a factor and the production special case is deleted.
The administrator is given something to pass on by hand whenever the system
cannot prove it delivered one itself.

A two-directional "if and only if" cannot be implemented. SMTP can accept and
queue a message while the client times out before reading the final reply, so
"email did not carry it" is not observable. The rule is therefore deliberately
asymmetric and fails towards giving the administrator a credential: a redundant
link is harmless, an unreachable account is the defect being fixed.

`UserInviteResponse.delivery` becomes an enum replacing the hardcoded string:

| Value | Meaning | Credential returned |
|---|---|---|
| `sent` | A `250` acceptance was read from the server | No |
| `uncertain` | The message was written but no reply was read — timeout or dropped connection | Yes |
| `not_configured` | SMTP is not enabled | Yes |
| `failed` | Connect, TLS, authentication, or the send was refused | Yes |

`uncertain` is a distinct value rather than folded into `failed` so the UI can
say the message *may* have arrived. It costs nothing in correctness: the
credential returned is the same one the message carried, so a duplicate
delivery cannot produce two divergent tokens.

Creating the user always succeeds. A broken mail server degrades invitation
delivery; it never blocks onboarding.

### Recovery from an interrupted request

A process that dies after persisting the user but before sending or replying
leaves an `INVITED` account whose credential nobody saw. This is not prevented
— it would need a two-phase commit across MongoDB and an SMTP server — it is
made recoverable.

`resend-invitation` is the single recovery path for every such case. It rotates
the token, applies the same delivery rule, and is reachable from the users list
for any account in `INVITED` state. The users list is therefore the recovery
surface: an account stuck in `INVITED` always has a working action next to it,
whatever went wrong the first time.

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

`Settings` gains a `public_base_url` property resolved in this order:

1. `PUBLIC_BASE_URL`, when set.
2. The single entry in `parsed_cors_origins`, when there is exactly one.
3. Otherwise unresolved (`None`).

Deriving in case 2 rather than adding a required setting is deliberate. A CORS
origin is self-validating: if it is wrong, the browser application cannot call
the API at all, so a deployment that works at all has a correct one. It is
already wired through the Helm configmap and `.env.example`, so the common
single-origin deployment needs no new configuration.

**Several origins never pick a winner.** CORS is an allow-list, not a
declaration of a canonical address; ordering within it carries no meaning, and
a deployment may legitimately allow an internal origin alongside the
user-facing one. Where an earlier draft of this design noted that "first is
arbitrary" and then used the first anyway, resolution now fails instead.
`ingress.host` is likewise not consulted: it is configured independently of
`corsOrigins` and the two can diverge.

Enabling SMTP while `public_base_url` is unresolved is rejected, with an error
naming `PUBLIC_BASE_URL` and the reason — several origins, or none. This
applies to development too: the default `.env` lists two origins, so testing
SMTP locally means setting `PUBLIC_BASE_URL`. `.env.example` gains it as a
commented line.

`PUBLIC_BASE_URL` is validated when present: an absolute `http` or `https` URL
with a host, no userinfo, no query, and no fragment. A trailing slash is
accepted and normalised away. A value failing validation is a startup error,
not a silently ignored one.

**Production requires `https`.** The activation request carries the invitation
credential and the password its owner is choosing, in one POST. Over plaintext
both are readable by anything on the path, and the link is long-lived enough —
seven days — for an intercepted one to be used later.

This applies to the resolved `public_base_url` whatever its source, not only to
an explicit override: a production deployment whose single CORS origin is
`http://` is rejected on exactly the same grounds. Development and test are
unaffected and keep `http`.

A resolved `http` base URL in production is a startup error rather than a
deferred one. Nothing working is broken by that: `session_cookie_secure` is
already forced true in production, so a production deployment served over
plaintext cannot hold a session at all and is therefore already non-functional.
Failing at startup names the real problem instead of letting it surface later
as an intercepted password.

The Host header is not used. It is attacker-controlled, and §16 requires not
trusting arbitrary forwarded headers; an activation link built from it would be
spoofable by anyone who can reach the API.

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

#### TLS is verified explicitly

Both TLS paths **must** pass an `ssl.create_default_context()`. Neither may be
left to the default.

This is not belt-and-braces. On this project's interpreter (3.13.7),
`smtplib.SMTP.starttls` and `SMTP_SSL.__init__` both fall back to
`ssl._create_stdlib_context()` when given no context, which has
`check_hostname=False` and `verify_mode=CERT_NONE`, where
`ssl.create_default_context()` has `check_hostname=True` and
`CERT_REQUIRED`. Connecting with the default therefore encrypts to whoever
answers, including an interceptor presenting any certificate at all, who would
read both the invitation token and the SMTP password. A verified context is
what makes `tls` and `starttls` mean anything.

With `starttls`, a server that does not advertise STARTTLS is a failure — the
send is never retried in the clear. `smtplib` raises `SMTPNotSupportedError`,
which is a connect-phase error and therefore classifies as `failed`, since no
message body was written.

#### Plaintext delivery is constrained

`smtp_security = "none"` puts the invitation token, and any credential used to
send it, on the wire in the clear.

- **`none` with a username is rejected in every environment.** Sending an SMTP
  password in the clear is never the intended configuration, and offering it as
  a checkbox invites it.
- **`none` is rejected in production** unless the host is a loopback address.
  The loopback exception exists for the one legitimate case — a mail relay
  running as a sidecar or on the same host, where the traffic never reaches a
  network — and is narrow enough to state as a rule rather than a judgement.
- **Outside production `none` is allowed**, and the test-connection result says
  in plain words that the connection was unencrypted, so it cannot be mistaken
  for a working secure configuration.

#### The sender classifies, the caller does not

`MailSender.send` **returns** an outcome and never raises for a delivery
problem:

```python
@dataclass(frozen=True, slots=True)
class SendOutcome:
    status: Literal["sent", "uncertain", "failed"]
    detail: str   # bounded, credential-free; empty when status is "sent"
```

Classification lives in the transport because only the transport knows which
protocol phase raised. An `SMTPException` or socket timeout does not by itself
say whether the message body was written — the caller, seeing only an
exception, would have to guess, and would guess `failed` for a message the
server may have queued.

The transport therefore tracks its phase explicitly and maps outcomes:

| Phase | Raised | Outcome | Why |
|---|---|---|---|
| Connect, `STARTTLS`, `login` | anything | `failed` | No message body was written |
| `send_message` | `SMTPRecipientsRefused`, `SMTPSenderRefused`, `SMTPDataError`, `SMTPNotSupportedError` | `failed` | A reply *was* read and it was a refusal |
| `send_message` | timeout, `SMTPServerDisconnected`, any other error | `uncertain` | The body may have been written and queued with the reply unread |
| `send_message` | nothing | `sent` | The `250` was read |

This is the only place `uncertain` is produced, which is what makes the
"Sending" section's rule — every non-`sent` outcome returns the credential —
implementable rather than aspirational.

`detail` is the transport's own short summary, capped in length, safe to show
an administrator, and carrying no part of the token.

### Sending

Sending is inline, within the invite request, because the delivery rule
requires the response to know whether the message was accepted.

The route takes the `SendOutcome` the transport returns and maps it straight
onto `delivery`; it performs no classification of its own. A `MailSender` that
raises despite the contract — a bug, not a delivery problem — is caught and
treated as `uncertain`, because an unexpected escape from `send` cannot rule
out that the body was written. No delivery problem ever propagates as an HTTP
error or prevents the account being created.

The product specification's "queued, retried with backoff" describes the
notification channels — high-volume, background, no user waiting. An invitation
is low-volume, interactive, and user-initiated, and the administrator wants to
know now whether to copy a link. When the Phase 5 delivery queue is built it
will reuse this transport; this path does not need it.

### The activation link carries the token in the fragment

The activation URL is:

```
{public_base_url}/accept-invitation#token={token}
```

**The token is in the fragment, not the query string.** A query string is
carried in the request line and lands in ingress and access logs, proxy logs,
browser history, and `Referer` headers on any outbound link — which would
contradict this design's own requirement that the credential is never logged.
A fragment is never sent to a server. It is the same reason OAuth implicit
responses use one.

This is available: the frontend uses `provideRouter` with the default path
location strategy and no `withHashLocation`, so the fragment is unused by
routing. Angular reads it from `ActivatedRoute.fragment`.

The page reads the fragment, holds the token in memory, and clears it from the
address bar immediately via `history.replaceState` so it does not persist in
browser history. It is submitted in the existing endpoint's POST body, which is
already how that endpoint accepts it — no API change.

### Email content

Plain text with a minimal HTML alternative. States who invited the recipient,
the application name, the activation link, and the expiry (7 days, from
`INVITATION_LIFETIME_DAYS`).

Per §16 the token is never logged: log records carry the recipient, the
outcome, and the SMTP server's response code, and nothing else.

### Manual delivery must hand over a usable link

When the delivery rule returns a credential, the administrator has to deliver
it by hand. Returning a bare token would make them construct the URL
themselves — and the current users UI renders exactly that, a bare
`invitation_token` in a `<code>` block, which the new page cannot consume.

`UserInviteResponse` therefore gains two fields:

- `invitation_url` — the complete activation link, built by the backend, which
  already knows `public_base_url`. Populated whenever a credential is returned
  and `public_base_url` resolves.
- `delivery_detail` — the `SendOutcome.detail` the transport produced, or
  `null`. Bounded in length and carrying no part of the token. This is what the
  `failed` message interpolates; without it the UI would have a reason to show
  and no field to read it from.

**The administrator is never left with a bare token.** When `public_base_url`
is unresolved, `invitation_url` is `null` and the frontend constructs the link
itself from `document.baseURI` — the origin the administrator is looking at —
and presents it identically. The backend-generated URL is always preferred when
present, so the canonical address stays canonical.

This does not reintroduce the Host-header risk rejected above, for two reasons.
It is a client-side convenience for display and copying, not a server-side
trust decision: the link is shown to an authenticated administrator already on
that origin, the server neither reads nor sends it, and nobody else's security
depends on it. And it is unreachable in any path that emails anything —
enabling SMTP requires a resolved `public_base_url`, so `uncertain` and
`failed` always carry a backend-built URL, and the fallback can only ever apply
to `not_configured`.

The users UI renders the link as the primary artefact with a copy control, not
the raw token, and its message differs per outcome:

| `delivery` | Message |
|---|---|
| `sent` | Invitation emailed to `{email}`. |
| `uncertain` | Sent to `{email}`, but the mail server did not confirm. Share this link if it does not arrive. |
| `not_configured` | No SMTP server is configured, so no email was sent. Share this link with `{email}`. |
| `failed` | Email to `{email}` failed: `{delivery_detail}`. Share this link instead. |

### Accept-invitation page

A new unauthenticated frontend route `accept-invitation`, reading the token
from the fragment as above, taking a password and a confirmation, posting to
the existing endpoint, and redirecting to login on success.

It must sit outside the authentication guard and before the wildcard route,
which currently swallows it. Invalid, expired, and already-accepted tokens all
surface the endpoint's single deliberately indistinct message rather than
revealing which. Arriving with no fragment at all shows the same message,
rather than an empty form that can only fail on submit.

`SETTINGS_TABS` in `services/deep_links.py` gains `"email"` for the new
settings tab. `deep_link` validates against that frozenset and raises for a tab
it does not know, so omitting this breaks any deep link to the tab.

### Throttling both invitation endpoints

Neither `invite` nor `resend-invitation` has a rate limit. With mail wired up
both become outbound-email triggers, which is a spam vector and a way to burn a
mail provider's sending reputation. Limiting only resend would leave `invite`
unlimited, so both are covered.

`ThrottleService` is reused for its storage, atomic counting, and
reserve-then-release semantics, but **not its existing scopes**. Its scopes
share one window (`self._window`, from `sign_in_throttle_window_minutes`, 15
minutes) and `user(user_id)` returns the key `user:{user_id}` — the key
password confirmation already counts against. Reusing it would put invitation
sends and password-confirmation failures in one bucket, each able to starve the
other.

Two changes:

1. `Scope` gains `window: timedelta | None = None`. `ThrottleService.reserve`
   passes `scope.window or self._window` to the store, which already takes a
   window per call. Existing scopes leave it `None` and are unaffected.
2. Two new scopes in their own key namespaces:

| Scope | Key | Limit | Window |
|---|---|---|---|
| `invitation_target(user_id)` | `invite-target:{user_id}` | 1 | 1 minute |
| `invitation_sender(admin_id)` | `invite-sender:{admin_id}` | 20 | 1 hour |

The per-target scope stops one invitee being mailed repeatedly. The per-sender
scope bounds what one administrator's account can emit in total, which is what
makes `invite` — where no target exists yet — limited at all. Both limits are
settings with these defaults, not literals.

**Reservation happens before the token is rotated.** `reserve` already counts
before the attempt for exactly this reason. Rotating first and then hitting the
limit would invalidate a token that is still in flight to the invitee, turning
a rate limit into a denial of service against a legitimate invitation.

**Every admitted attempt consumes the limit, whatever the delivery outcome.**
The costs being bounded are the outbound connection attempt and the token
rotation, and both happen for `failed` and `not_configured` as much as for
`sent`. Refunding unsuccessful sends would let a misconfigured server be
retried without limit, which is precisely when retrying is most futile. A
request refused by the throttle itself is released, as `reserve` already does,
since it never happened.

## Testing

- The delivery rule, driven with a fake `MailSender`, one case per enum value:
  acceptance returns no credential and `sent`; a timeout after writing returns
  the credential and `uncertain`; disabled SMTP returns it and
  `not_configured`; a refused send returns it and `failed`.
- Production is no longer special: all four cases assert identically with
  `environment="production"`.
- `public_base_url` resolution: exactly one origin derives it; several origins
  leave it unresolved; none leaves it unresolved; the override wins over both.
- `PUBLIC_BASE_URL` validation: relative, non-HTTP scheme, userinfo, query, and
  fragment are each rejected at startup; a trailing slash is normalised.
- An `http` base URL is rejected in production and accepted in development and
  test, whether it came from the override or was derived from a single CORS
  origin; an `https` one is accepted everywhere.
- Both TLS paths are constructed with a context that has `check_hostname` set
  and `verify_mode` of `CERT_REQUIRED` — asserted on the context the transport
  builds, so a future refactor that drops the argument and inherits
  `smtplib`'s unverified default fails the test.
- A `starttls` connection to a server not advertising STARTTLS is `failed`, and
  no message is written in the clear.
- `smtp_security="none"` is rejected with a username in every environment;
  rejected in production against a non-loopback host; accepted in production
  against a loopback host; accepted outside production, where the
  test-connection detail states the connection was unencrypted.
- Enabling SMTP is rejected without a host, without a from address, and with an
  unresolved public base URL.
- The activation link carries the token in the fragment and never the query
  string, and the token appears in no log record for any of the four outcomes.
- `invitation_url` is populated whenever a credential is returned and the base
  URL resolves, and is `null` — with the token still returned — when it does not.
- Transport phase classification, against a fake SMTP client that raises at a
  chosen phase: a connect, `STARTTLS`, or `login` error is `failed`; a
  recipient, sender, or data refusal during `send_message` is `failed`; a
  timeout or disconnection during `send_message` is `uncertain`; a clean send
  is `sent`. The route maps each straight through without reclassifying, and a
  `MailSender` that raises in breach of its contract yields `uncertain`.
- `delivery_detail` is populated for `failed` and `uncertain`, is absent for
  `sent`, is capped in length, and never contains any part of the token.
- The frontend falls back to a `document.baseURI` link when `invitation_url` is
  `null`, prefers the backend URL whenever it is present, and never shows a
  bare token with no link.
- `smtp_security` selects the right client and upgrade path.
- The test-connection endpoint records its outcome to the `smtp_last_test_*`
  fields and sends no message.
- The accept-invitation page: valid token activates and redirects; invalid,
  expired, and absent tokens show the same indistinct failure; mismatched
  confirmation is refused client-side; the fragment is cleared from the address
  bar on load.
- Throttling: a second resend for one target inside the window is refused; the
  21st invitation from one administrator inside the hour is refused; a refused
  attempt does not rotate the token; `failed` and `not_configured` outcomes
  consume the limit; and invitation scopes do not share a bucket with
  password-confirmation failures.

No test performs real network I/O.

## Consequences

The API contract changes: `UserInviteResponse.delivery` becomes an enum,
`invitation_token` is populated under a new condition, and `invitation_url` and
`delivery_detail` are added. Both invitation endpoints can now answer `429`.
`docs/openapi.json` must be regenerated, since `make check` compares it.

`Scope` in `services/throttling.py` gains an optional per-scope window. Every
existing scope leaves it unset and keeps the shared window, so sign-in and
password-confirmation limits are unchanged.

A production deployment whose resolved `public_base_url` is `http` will now
refuse to start, where before it started and was quietly unable to hold a
session. This surfaces an existing misconfiguration rather than creating one,
but it is a behaviour change on upgrade and belongs in the release notes.

Existing `INVITED` accounts stranded by the current behaviour are not migrated.
Once this ships, an administrator resends the invitation and the token is
returned or delivered. This is deliberate: minting new tokens for existing
accounts without an administrator asking would be a security change, not a fix.
