# Mist Config Guardian

## Product and Technical Specification

**Status:** Baseline specification
**Target:** Standalone, self-hosted application
**Source application:** `mist_automation`
**Primary stack:** FastAPI, Angular, MongoDB, Redis/Celery, InfluxDB
**Deployment:** Docker Compose and Helm/Kubernetes

## 1. Purpose

Mist Config Guardian continuously records recoverable versions of Juniper Mist
configuration objects, lets authorized administrators navigate and compare those
versions, and restores an object, site, or organization to a selected point in
time.

The application also monitors network behavior after device configuration
changes. It correlates audit events with per-device configuration events,
compares pre-change and post-change health, and reports whether a change caused
degradation. AI analysis is optional; deterministic analysis remains available
without an LLM.

## 2. Product goals

1. Maintain a trustworthy, queryable history of every supported, restorable Mist
   configuration object.
2. Recover from missed webhooks through scheduled reconciliation.
3. Restore configurations safely across object dependencies and regenerated
   Mist UUIDs.
4. Support point-in-time restore at organization, site, and object scope.
5. Detect operational impact after configuration changes using device events,
   SLEs, topology, routing, client, and incident data.
6. Correlate all devices affected by one administrator action into one change
   group.
7. Provide a simple standalone application that can manage multiple Mist
   organizations in one deployment.
8. Preserve a complete audit trail for backup, monitoring, approval, and restore
   activity.

## 3. Non-goals for the first release

- Multi-customer SaaS tenancy.
- Editing arbitrary Mist configuration directly from the application.
- Restoring read-only, derived, action-only, or otherwise non-reversible Mist
  endpoints.
- Fully autonomous AI-triggered rollback.
- Reproducing unrelated automation, workflow, reporting, power scheduling, MCP,
  or digital-twin features from `mist_automation`.
- Final visual design. The first release defines information architecture,
  interaction requirements, and accessibility constraints only.

## 4. Users and authorization

### 4.1 Authentication methods

The application supports:

- Local accounts.
- Mist-account authentication, subject to a discovery spike confirming the
  supported Mist authentication flow and a reliable super-user privilege check.

The organization stores only a dedicated read-only service-account token. It is
used for unattended backup, reconciliation, webhook validation, and monitoring.
Every Mist write uses a freshly authenticated administrator's delegated Mist
credential so Mist's native audit trail attributes the change to that
administrator.

### 4.2 Roles

| Role | Capabilities |
|---|---|
| Viewer | View organizations, versions, diffs, monitoring results, and audit history |
| Operator | Viewer capabilities plus run manual backups, reconciliation, simulations, and monitoring |
| Administrator | Full configuration, user, credential, retention, webhook, approval, and restore planning access |
| Mist super user | May execute restores for explicitly authorized organizations when also granted the required application role |

Restore execution requires both application authorization and a freshly
authenticated Mist super-user identity for the target organization. A local
administrator must link and re-authenticate a Mist super-user account before
execution. Mist privilege in one organization does not grant access to another.
The application never escalates or falls back to the read-only service account
for any Mist write.

### 4.3 Approval policy

Each organization may enable two-person approval and configure thresholds, such
as:

- Any organization-scope restore.
- Any exact restore that deletes objects.
- A restore affecting more than a configured number of objects.
- A restore involving selected sensitive object types.

The requester cannot approve their own request. The approved plan is immutable;
any plan change invalidates approval.

## 5. Organization onboarding

An administrator adds one or more Mist organizations. Each organization stores:

- Mist organization ID and display name.
- An encrypted dedicated read-only service-account API token for unattended
  reads.
- Webhook provisioning mode: automatic or manual.
- Public webhook endpoint and per-organization signing secret.
- Initial snapshot status.
- Reconciliation schedule and timezone.
- Configuration and monitoring retention policies.
- Monitoring durations, intervals, and degradation thresholds.
- Approval policy.
- Notification channel configuration.
- AI provider configuration or an explicit disabled state.

Onboarding verifies the token, confirms organization access, discovers supported
capabilities, validates webhook reachability, and runs a full initial snapshot.
Incremental processing is not considered healthy until that initial snapshot
completes.

### 5.1 Webhook provisioning

Two modes are supported:

1. **Automatic:** with explicit administrator consent and fresh Mist super-user
   authentication, the application creates or updates required audit and
   device-event webhooks and rotates secrets using that administrator's
   delegated credential. Unattended checks use the read-only service token;
   detected drift creates an alert and requires an administrator to re-authenticate
   before repair.
2. **Manual:** the application provides exact Mist settings and validates the
   resulting webhook configuration.

Webhook health shows last receipt time, signature status, configured topics,
delivery gaps, and detected configuration drift.

## 6. Supported object registry

The object registry is the contract for backup and restore behavior. The first
release targets every Mist configuration endpoint that has safe read and inverse
write operations, including restorable endpoints not covered by the current
`mist_automation` registry.

An endpoint is included only when all required capabilities are defined and
tested:

- Scope: organization or site.
- List/get operation.
- Create, update, and delete behavior as applicable.
- Stable identity and display-name extraction.
- Singleton versus collection semantics.
- Fields excluded from hashing or restore payloads.
- Explicit dependency paths.
- Implicit containment dependencies.
- Restore ordering.
- UUID rewrite locations.
- API version and minimum Mist capability.
- Rate-limit weight.
- Redaction rules for sensitive values.

Read-only, derived, action-only, or non-reversible endpoints are excluded from
the backup/restore registry rather than presented as recoverable.

The UI exposes a capability matrix so administrators can see coverage and why an
endpoint is excluded.

## 7. Backup and versioning

### 7.1 Initial snapshot

On onboarding, the application:

1. Discovers all supported objects.
2. Fetches full canonical configuration for each object.
3. Normalizes volatile and server-generated fields.
4. Extracts explicit and implicit references.
5. Stores an immutable version and content hash.
6. Records a consistent snapshot manifest containing the collection start and
   completion times, object counts, failures, and coverage.
7. Retries transient failures and marks the snapshot incomplete if any required
   scope cannot be captured.

An incomplete initial snapshot cannot be used for organization-wide restore.

### 7.2 Incremental webhook capture

Audit webhooks are stored durably before asynchronous processing. Processing is
idempotent and safe under duplicate, delayed, and out-of-order delivery.

For each actionable audit event:

1. Resolve the organization from the endpoint and payload.
2. Deduplicate using organization, webhook topic, event ID, and payload hash.
3. Persist the raw payload, selected headers, signature result, and receipt time.
4. Resolve all affected objects.
5. Fetch current canonical state from Mist when the webhook does not contain a
   complete authoritative object.
6. Compare against the latest stored version.
7. Store a new immutable version only when canonical content or deletion state
   changed.
8. Link versions to the audit event, actor, method, message, and `audit_id`.

A deletion creates a tombstone version retaining the prior configuration and
dependency metadata needed for recovery.

### 7.3 Scheduled reconciliation

Each organization has a configurable reconciliation schedule. Reconciliation:

- Enumerates all registered object types.
- Adds objects missing from history.
- Creates versions for content drift not observed through webhooks.
- Creates tombstones for objects no longer present.
- Detects webhook delivery gaps.
- Never rewrites immutable historical versions.
- Reports partial failures and retries within Mist rate limits.

Manual reconciliation is available to operators and administrators.

### 7.4 Identity model

Mist UUID alone is not a safe historical identity because UUIDs are regenerated
when deleted objects are recreated.

Every object has:

- `logical_object_id`: stable application identity across restores.
- `mist_object_id`: UUID used by the current Mist object incarnation.
- `incarnation`: monotonically increasing number for each regenerated UUID.
- `scope_key`: organization, optional site logical identity, and object type.
- `version`: monotonically increasing within the logical object and scope.

All uniqueness, lookup, and correlation keys include `organization_id`.
Singleton objects include their scope in uniqueness keys. This avoids the
single-organization and UUID-only assumptions in the source application.

### 7.5 Canonicalization and sensitive data

Canonicalization removes only registry-declared volatile fields, sorts
order-insensitive structures, and preserves order-sensitive structures.

Secrets returned by Mist are encrypted at rest. Values that Mist never returns
cannot be restored and must be identified in preflight as required administrator
input. API responses and logs redact secrets by default.

### 7.6 Retention

Configuration and monitoring retention are independently configurable per
organization.

Retention jobs:

- Preserve versions referenced by active restore plans, approvals, legal holds,
  or restore execution records.
- Preserve at least one recoverable baseline preceding the retention boundary.
- Preview deletion counts before a policy change is applied.
- Write an immutable retention audit event.

## 8. Version navigation and comparison

The application provides:

- Organization, site, object type, object, actor, event, and date filters.
- A change activity timeline.
- Per-object version history with create, update, delete, and restore markers.
- A/B comparison between arbitrary versions.
- Structured and raw JSON diff views.
- Changed-field grouping and change magnitude.
- Links between audit events, object versions, monitoring groups, and restores.
- A point-in-time browser that reconstructs the selected scope as it existed at
  a timestamp.

Default object detail behavior selects the two newest versions for comparison.
Deleted objects remain discoverable and visibly marked.

## 9. Point-in-time restore

### 9.1 Restore scopes

- Individual object.
- Entire site.
- Entire organization.

The administrator selects a timestamp and one of two modes:

- **Non-destructive:** recreate missing objects and revert modified objects, but
  keep objects created after the selected timestamp.
- **Exact:** additionally delete in-scope objects created after the selected
  timestamp so the selected scope matches the historical state.

Deleted parents always restore their complete historical dependency subtree.
The user cannot exclude descendants from that subtree.

### 9.2 Restore plan

Every restore begins with an immutable preflight plan. The planner compares:

1. The desired point-in-time state.
2. The latest stored state.
3. Fresh live state fetched from Mist.

The plan lists:

- Creates, updates, deletes, and no-ops.
- Direct and transitive dependencies.
- Objects outside the selected scope that contain references requiring UUID
  rewrites.
- Sensitive values that require input.
- Unsupported or blocked operations.
- Expected API calls and execution order.
- Concurrency and rate-limit constraints.
- Blast radius by organization, site, object type, and device.
- Monitoring that will follow the restore.
- Whether policy requires approval.
- Compensating actions for each write.

Any live-state change after plan generation makes the plan stale. Execution
requires regeneration or an explicit revalidation that produces the same plan
hash.

Preflight also verifies that the executor has an active delegated Mist
credential, super-user rights in the target organization, sufficient token
lifetime for the estimated operation, and permission for every planned write.
If that credential is unavailable, expires, or loses authorization, execution
is blocked. It cannot switch identities or fall back to the read-only service
account.

### 9.3 Dependency graph

Dependencies come from:

- Registry-declared field paths.
- UUID-reference extraction from canonical object payloads.
- Implicit containment, such as site-scoped objects depending on their site.
- Known singleton and template relationships.

The planner constructs a directed graph and validates it before writing:

- Creates and updates execute in topological parent-first order.
- Deletes execute in reverse topological child-first order.
- Site creation precedes all site-scoped writes.
- Cycles are either handled by a registry-defined multi-phase strategy or block
  the restore.
- Dependency closure is recursive, not limited to one parent level.

### 9.4 UUID remapping

When Mist recreates an object with a new UUID, the executor:

1. Records `old_uuid -> new_uuid` in the restore execution.
2. Associates the new UUID with the existing logical object and increments its
   incarnation.
3. Rewrites all registry-known and dynamically discovered references in pending
   restore payloads.
4. Finds currently existing Mist objects, including objects outside the
   restored subtree, that still reference the old UUID.
5. Adds required reference updates to the preflight plan.
6. Re-fetches each object immediately before update and verifies its expected
   hash.
7. Verifies after execution that no live restorable object still references an
   replaced UUID.
8. Stores new `RESTORED` versions for every object created or modified by the
   operation.

UUID remapping is scoped by organization, object type, and containment context;
the executor never performs an unqualified global string replacement.

### 9.5 Execution and failure policy

Mist does not provide transactional multi-object writes. The executor therefore:

1. Acquires an organization-scoped restore lock.
2. Revalidates live state and the executing Mist super user's delegated
   credential.
3. Captures a pre-restore safety snapshot of every object the plan may modify.
4. Executes in dependency order.
5. Verifies each write by reading it back from Mist.
6. Stops on the first failure.
7. Produces a compensating rollback plan from the safety snapshot.
8. Requires explicit administrator confirmation before compensation unless the
   organization policy pre-authorizes automatic compensation.
9. Marks the execution as succeeded, partially applied, compensated, or failed.

The UI never reports success while verification or required reference rewrites
remain incomplete.

### 9.6 Restore audit trail

The audit record includes requester, approver, reason, selected timestamp, mode,
plan hash, before/after hashes, API operations, UUID mappings, errors,
compensation, verification, source IP, application identity, Mist identity, and
timestamps. Each Mist API write records the delegated identity and Mist request
correlation metadata when available.

Restore-originated webhooks are correlated to the restore execution and do not
create duplicate or misleading user-change records.

## 10. Change impact monitoring

### 10.1 Trigger and correlation flow

The standalone app retains and hardens the current `mist_automation` approach:

1. `AP_CONFIG_CHANGED_BY_USER`, `AP_CONFIG_CHANGED_BY_RRM`,
   `SW_CONFIG_CHANGED_BY_USER`, and `GW_CONFIG_CHANGED_BY_USER` start or merge a
   per-device monitoring session.
2. The session captures its baseline and waits for `AP_CONFIGURED`,
   `SW_CONFIGURED`, or `GW_CONFIGURED`.
3. A `*_CONFIGURED` event confirms that the configuration was applied and starts
   post-change monitoring.
4. If the pre-change event was missed, `*_CONFIGURED` acts as a fallback trigger
   and the session records reduced baseline confidence.
5. `*_CONFIG_FAILED` and `*_CONFIG_REVERTED` immediately escalate impact.
6. Related incident and resolution events are correlated throughout the
   monitoring window.

All correlation keys are multi-organization safe:

- Change group: `organization_id + audit_id`.
- Active device session: `organization_id + device_mac`.
- Webhook deduplication: `organization_id + topic + event identity`.

Handlers tolerate audit and device events arriving in either order. Unmatched
events are retained for a configurable correlation window and replayed when
their counterpart arrives.

### 10.2 Change groups

One Mist administrator action may push configuration to many devices. All
sessions sharing `organization_id + audit_id` belong to one change group.

The group provides:

- Actor, message, source, before/after change, and timestamps.
- Affected sites and devices.
- Per-device state and results.
- Aggregate SLE and validation outcomes.
- Worst severity.
- Group-level deterministic and optional AI assessment.
- Links to the corresponding backup versions and restore execution.

### 10.3 Monitoring pipeline

Per-device lifecycle:

`pending -> baseline_capture -> awaiting_config -> monitoring -> validating -> completed`

Terminal states are `completed`, `failed`, and `cancelled`.

Monitoring duration, intervals, timeout, and thresholds are configurable by
device type and organization.

The pipeline reuses the source application's validated checks where applicable:

- Connectivity and reachability.
- Device stability and relevant events.
- SLE baseline, snapshots, trend, and degradation.
- Client count and client-impact changes.
- Topology, loops, and black holes.
- Port flapping.
- DHCP health.
- Virtual Chassis integrity.
- OSPF/BGP adjacency.
- Configuration drift and push failures.
- PoE budget.
- WAN failover.
- LAG/MCLAG integrity.

Checks declare applicable device types, prerequisites, data freshness, skip
reasons, warning/failure thresholds, and evidence.

### 10.4 Baseline confidence

Each assessment has a confidence value based on:

- Whether a pre-change event was received.
- Whether baseline collection completed before `*_CONFIGURED`.
- Data availability and freshness.
- Number of successful monitoring polls.
- Missing webhooks or API failures.

The app distinguishes “no impact detected” from “insufficient evidence.”

### 10.5 Deterministic analysis

Deterministic rules always run and produce:

- Severity: none, informational, warning, or critical.
- Findings with evidence and affected devices.
- Resolved versus active incidents.
- SLE deltas and threshold comparisons.
- Recommended operator actions.
- Confidence and missing-data warnings.

The deterministic result is authoritative for automation and alert thresholds.
AI output cannot lower deterministic severity or suppress evidence.

### 10.6 Optional AI assistance

AI is provider-agnostic and optional. Providers implement a common adapter for
model selection, credentials, timeout, token limits, and health checks.

AI receives a bounded, redacted evidence package containing the change,
deterministic findings, relevant diffs, SLE deltas, incidents, topology changes,
and device metadata. It produces structured output:

- Impact assessment.
- Root-cause hypothesis.
- Evidence references.
- Recommended remediation.
- Confidence.

AI output is clearly labeled, stored with provider/model metadata, and never
executes a restore. If AI is unavailable, deterministic analysis completes
normally.

## 11. Notifications

Supported channels:

- In-app notifications.
- Email.
- Generic outbound webhook.
- Slack.
- Microsoft Teams.

Policies filter by organization, severity, event type, and destination.
Notifications cover harmful changes, config apply failures, device reverts,
restore approval requests, restore failures, compensation results, missed
webhooks, reconciliation failures, and credential expiry.

Delivery is queued, retried with backoff, deduplicated, and audited. Secrets are
redacted from payloads.

## 12. UI information architecture

### 12.1 Primary navigation

- Overview.
- Changes.
- Configuration history.
- Restore center.
- Impact monitoring.
- Organizations.
- Notifications.
- Administration.

### 12.2 Overview

Shows backup health, webhook health, reconciliation freshness, active monitoring
groups, recent harmful changes, pending approvals, failed restores, storage use,
and organization filters.

### 12.3 Changes

Shows audit-centric groups rather than isolated object writes. Selecting a change
opens its object versions, affected devices, monitoring status, evidence, and
restore actions.

### 12.4 Configuration history

Supports browsing by organization, site, and object hierarchy. Object detail
uses a persistent version timeline, A/B pins, structured diff, raw JSON view,
actor metadata, and per-version restore entry points.

### 12.5 Point-in-time browser

The admin chooses scope and time, browses the reconstructed hierarchy, compares
it with live state, chooses exact or non-destructive mode, and creates a
preflight plan.

### 12.6 Restore center

Contains drafts, pending approvals, running executions, completed executions,
partial failures, UUID remaps, compensation plans, and verification results.
Execution progress streams in real time.

### 12.7 Impact monitoring

The primary view is change-group centric, with drill-down to device sessions.
It includes the change, monitoring timeline, deterministic findings, AI
assessment, SLE charts, incidents, checks, topology evidence, and confidence.

### 12.8 Accessibility and responsiveness

- Keyboard-accessible workflows.
- WCAG 2.1 AA contrast and focus behavior.
- Status is never conveyed by color alone.
- Destructive actions use explicit labels and impact summaries.
- Dense comparison and restore screens target desktop first; monitoring and
  alert views remain usable on tablets.

## 13. Service architecture

```text
Mist Cloud
   |
   +-- audit webhooks -----------+
   +-- device-event webhooks ----+--> Webhook API
   +-- REST APIs ----------------+        |
                                         v
Angular UI --> FastAPI API --> MongoDB <-> Celery workers
                  |              |             |
                  |              |             +-- snapshot/reconciliation
                  |              |             +-- restore planner/executor
                  |              |             +-- impact monitoring
                  |              |             +-- notifications
                  |              |
                  |              +--> InfluxDB (time-series SLE/telemetry)
                  |
                  +--> Redis (broker, locks, cache, real-time fan-out)
                  +--> optional LLM providers
```

### 13.1 Components

- **API service:** authentication, authorization, REST APIs, WebSockets, webhook
  ingress, validation, and UI hosting.
- **Worker service:** backup, reconciliation, restore, monitoring, AI, retention,
  and notification tasks.
- **Scheduler:** reconciliation, retention, health checks, and cleanup.
- **MongoDB:** organizations, users, object versions, manifests, webhook events,
  dependencies, plans, approvals, executions, monitoring metadata, and audit
  records.
- **InfluxDB:** SLE and time-series monitoring samples.
- **Redis:** Celery broker/backend, distributed locks, caches, idempotency
  coordination, and real-time event fan-out.

Webhook ingress may run as a separately scalable deployment with the same
application image.

### 13.2 Reliability rules

- Persist webhooks before acknowledging success.
- Use at-least-once queues and idempotent workers.
- Use organization-aware idempotency keys.
- Use bounded retries with jitter for transient Mist API failures.
- Respect Mist rate limits globally and per organization.
- Move exhausted jobs to a visible dead-letter state.
- Use distributed locks for initial snapshots, reconciliation, and restores.
- Expose readiness, liveness, dependency, queue-depth, and webhook-lag metrics.

## 14. Core data model

| Entity | Purpose |
|---|---|
| Organization | Mist connection, policies, schedules, capabilities, and health |
| User / IdentityLink | Local or Mist identity, roles, and organization access |
| ObjectTypeDefinition | Versioned registry metadata and restore capability |
| LogicalObject | Stable identity across Mist UUID incarnations |
| ObjectIncarnation | Historical mapping from logical identity to Mist UUID |
| ObjectVersion | Immutable canonical configuration, hash, event, references, and tombstone state |
| SnapshotManifest | Coverage and consistency metadata for a full or scoped snapshot |
| WebhookEvent | Raw durable event, signature, deduplication, routing, and processing state |
| AuditChange | Normalized administrator change linked to versions |
| DependencyEdge | Typed reference with source field path and validity interval |
| RestorePlan | Immutable desired/live comparison, graph, operations, and plan hash |
| RestoreApproval | Independent approval decision and policy evidence |
| RestoreExecution | Operation state, safety snapshot, UUID map, verification, and compensation |
| ChangeGroup | Organization-scoped `audit_id` group across affected devices |
| MonitoringSession | Per-device pipeline and evidence |
| Finding | Deterministic or AI finding with evidence and confidence |
| NotificationDelivery | Destination, payload metadata, attempts, and result |
| AuditRecord | Append-only security and administrative activity |

Large raw payloads may be compressed, but metadata required for filtering remains
indexed.

## 15. API surface

All APIs are versioned under `/api/v1`.

### 15.1 Organizations and identity

- `GET/POST /organizations`
- `GET/PATCH/DELETE /organizations/{id}`
- `POST /organizations/{id}/verify`
- `POST /organizations/{id}/initial-snapshot`
- `GET/POST /organizations/{id}/webhooks`
- `POST /organizations/{id}/webhooks/validate`
- `GET/PATCH /organizations/{id}/policies`
- `GET/POST/PATCH /users`
- `POST /auth/local/login`
- `GET /auth/mist/start`
- `GET /auth/mist/callback`

### 15.2 History and reconciliation

- `GET /objects`
- `GET /objects/{logical_id}`
- `GET /objects/{logical_id}/versions`
- `GET /versions/{id}`
- `GET /diff?from={version_id}&to={version_id}`
- `GET /state?organization_id=...&scope=...&at=...`
- `POST /reconciliations`
- `GET /reconciliations/{id}`
- `GET /object-types/capabilities`

### 15.3 Restore

- `POST /restore-plans`
- `GET /restore-plans/{id}`
- `POST /restore-plans/{id}/revalidate`
- `POST /restore-plans/{id}/request-approval`
- `POST /restore-plans/{id}/approve`
- `POST /restore-plans/{id}/reject`
- `POST /restore-plans/{id}/execute`
- `GET /restore-executions/{id}`
- `POST /restore-executions/{id}/create-compensation-plan`
- `POST /restore-executions/{id}/execute-compensation`

### 15.4 Monitoring

- `GET /change-groups`
- `GET /change-groups/{id}`
- `POST /change-groups/{id}/reanalyze`
- `GET /monitoring-sessions`
- `GET /monitoring-sessions/{id}`
- `POST /monitoring-sessions/{id}/cancel`
- `GET /monitoring-sessions/{id}/sle`
- `GET /monitoring-settings`
- `PATCH /monitoring-settings`

### 15.5 Operations

- `POST /webhooks/mist/{organization_endpoint_id}`
- `GET /webhook-events`
- `GET /audit-records`
- `GET/PATCH /notification-policies`
- `POST /notification-policies/{id}/test`
- `GET /health`
- `GET /ready`

Mutating endpoints accept idempotency keys. List endpoints use cursor pagination.
Long-running operations return job IDs and stream progress over WebSockets.

## 16. Security requirements

- Encrypt the read-only Mist service token, delegated Mist credentials, webhook
  secrets, SMTP credentials, notification secrets, and LLM credentials at rest.
- Support a Kubernetes secret or external secret provider for the master key.
- Never place secrets in URLs, logs, diffs, AI prompts, or notification bodies.
- Verify Mist webhook signatures and bind each endpoint to one organization.
- Support optional source IP allowlists without trusting arbitrary forwarded
  headers.
- Require CSRF protection for cookie-authenticated browser requests.
- Rate-limit authentication, webhook, restore, and AI endpoints.
- Require recent re-authentication for restore execution and credential changes.
- Execute every Mist write, including webhook provisioning and restore, with the
  current administrator's delegated Mist super-user credential; block on expiry
  or loss of privilege and never fall back to the read-only service account.
- Require MFA for local administrators.
- Record append-only audit events for authentication, authorization changes,
  credential use, policy changes, approvals, and restores.
- Scope every database query and uniqueness constraint by organization where
  applicable.
- Run containers as non-root with read-only root filesystems where practical.
- Generate an SBOM and scan images and dependencies in CI.

## 17. Deployment

### 17.1 Docker Compose

The supported Compose bundle includes:

- API/web UI.
- Celery worker.
- Celery scheduler.
- MongoDB.
- Redis.
- InfluxDB.

Optional profiles include a separate webhook ingress and local development
services. Persistent volumes, health checks, resource guidance, and backup
instructions are mandatory.

### 17.2 Helm/Kubernetes

The Helm chart supports:

- Independent API, webhook, worker, and scheduler deployments.
- Horizontal API/webhook scaling.
- Worker queue selection and scaling.
- Ingress and TLS.
- Existing or bundled data services.
- Secrets and external secret integration.
- Pod disruption budgets, resource requests/limits, probes, and network
  policies.
- Database migrations as controlled jobs.
- Upgrade and rollback documentation.

MongoDB, Redis, and InfluxDB production high availability remain deployment
operator choices; the chart must support external managed instances.

## 18. Observability and operations

- Structured JSON logs with correlation IDs for webhook, audit change, backup,
  restore plan, execution, change group, and device session.
- Prometheus-compatible metrics for API latency, queue depth, task failures,
  Mist API rate limits, webhook lag, reconciliation age, backup coverage,
  restore duration, monitoring gaps, and notification delivery.
- Admin-visible job logs and errors with actionable remediation.
- Configurable health alerts.
- Export and restore procedures for MongoDB and InfluxDB.
- Schema and registry migrations are versioned and restart-safe.

## 19. Extraction plan from `mist_automation`

### 19.1 Reuse with adaptation

- `backend/app/modules/backup`: object registry, canonical version capture,
  reference extraction, backup workers, restore simulation, and cascade restore.
- `backend/app/modules/impact_analysis`: event handling, session lifecycle,
  change groups, monitoring workers, checks, SLE, topology, and deterministic/AI
  analysis.
- Unified webhook signature verification, enrichment, persistence, and routing.
- Backup timeline, object detail, compare, restore, cascade dialog, webhook
  monitor, and impact-analysis Angular components.
- Existing unit tests for version consistency, restore simulation, cascade
  restore, webhook APIs, and impact checks.

### 19.2 Required changes before reuse

- Replace singleton `SystemConfig` organization assumptions with
  organization-scoped services and credentials.
- Change object/version uniqueness from UUID-only to organization, logical
  identity, scope, and version.
- Change monitoring-session uniqueness from device MAC to organization plus
  device MAC.
- Change change-group uniqueness from `audit_id` to organization plus
  `audit_id`.
- Replace one-level cascade handling with recursive graph planning.
- Add exact and non-destructive point-in-time restore planning.
- Expand UUID remapping to live objects outside the restored subtree.
- Add stale-plan detection, organization locks, safety snapshots,
  compensating plans, approvals, and read-after-write verification.
- Separate deterministic analysis from optional provider-agnostic AI.
- Remove dependencies on workflow automation, global chat, MCP, power
  scheduling, reporting, and unrelated administration.
- Expand and test the restorable endpoint registry.

### 19.3 Do not copy

- Global single-organization configuration.
- UUID-only version indexes.
- Broad exception handling that silently skips restore or correlation failures.
- Git backup integration unless separately approved for a later release.
- Digital Twin dependencies in the restore flow.

## 20. Delivery phases

### Phase 1: Foundation

- Standalone repository and build pipeline.
- Multi-organization model and encrypted credentials.
- Local authentication, roles, and audit trail.
- Webhook ingress, persistence, signature verification, and provisioning.
- Initial snapshot and reconciliation framework.
- Registry capability matrix.

### Phase 2: History

- Complete supported-object registry.
- Immutable logical identity and incarnation model.
- Incremental versions, tombstones, references, and retention.
- History, timeline, A/B comparison, and point-in-time state APIs/UI.

### Phase 3: Restore

- Recursive dependency graph.
- Exact and non-destructive restore plans.
- UUID remapping and external live-reference updates.
- Approval policies, execution locks, verification, and compensation.
- Object, site, and organization restore UI.

### Phase 4: Impact monitoring

- Hardened event correlation and change groups.
- Per-device monitoring pipeline and deterministic findings.
- SLE, event, topology, routing, client, and device checks.
- Monitoring UI and alerting.

### Phase 5: AI and distribution

- Provider-agnostic AI adapters.
- Mist-account authentication, subject to discovery validation.
- Email, webhook, Slack, and Teams integrations.
- Production Docker Compose and Helm packages.
- Upgrade, backup, recovery, security, and operator documentation.

## 21. Acceptance criteria

### Backup and history

- Adding an organization produces a complete initial snapshot or an explicit
  incomplete state with object-level errors.
- Duplicate delivery of the same webhook produces no duplicate version.
- A missed webhook is detected and repaired by reconciliation.
- The same object UUID in two organizations cannot collide.
- A recreated object retains one logical history across UUID incarnations.
- An admin can compare any two retained versions.

### Restore

- An object restore previews every operation and dependency before execution.
- Restoring a deleted site recreates its complete historical subtree.
- All regenerated UUIDs are mapped and every affected live reference is updated
  or the plan is blocked.
- Exact mode identifies and, after confirmation/approval, deletes post-timestamp
  objects.
- Non-destructive mode preserves post-timestamp objects.
- A changed live object invalidates a stale restore plan.
- Execution stops on first failure and produces a verified compensating plan.
- Success requires read-after-write verification and zero unresolved replaced
  UUID references among registered objects.
- Approval thresholds and separation of duties are enforced.

### Monitoring

- A pre-config device event captures baseline and waits for its configured event.
- A configured event without a pre-config event creates a lower-confidence
  fallback session.
- Out-of-order audit and device events correlate within the configured window.
- One admin action affecting multiple devices appears as one organization-scoped
  change group.
- Deterministic analysis completes when no LLM is configured.
- AI failure does not fail or weaken deterministic analysis.
- Config failures, device reverts, critical incidents, and configured SLE
  degradation produce alerts according to policy.

### Security and deployment

- Only administrators and authorized Mist super users can execute restores.
- Every restore write is submitted with the executor's delegated Mist
  super-user credential and is attributable to that identity in both application
  and Mist audit records.
- Organization data and credentials remain isolated by authorization and query
  scope.
- The stored service-account token is read-only and cannot modify Mist
  configuration.
- Secrets are encrypted and absent from logs, diffs, prompts, and notifications.
- The application installs successfully through both documented Docker Compose
  and Helm paths.
- Restore, reconciliation, and monitoring jobs survive worker restart without
  duplicate writes.

## 22. Discovery items before implementation

These items do not change the product direction but must be resolved during
technical design:

1. Confirm the supported Mist account authentication mechanism, delegated token
   exchange and lifetime, logout behavior, super-user privilege endpoint, and
   that delegated API writes are attributed to the administrator in Mist audit
   records. Restore execution cannot ship until this is verified.
2. Produce the complete restorable endpoint matrix from the current Mist API
   version and verify create/update/delete behavior in a test organization.
3. Identify fields that Mist omits or redacts on read and define administrator
   input requirements for restore.
4. Confirm webhook payload identity and ordering guarantees for every required
   audit and device-event topic.
5. Benchmark initial snapshot, reconciliation, point-in-time reconstruction, and
   dependency planning against a large organization.
6. Define default retention, monitoring durations, alert thresholds, and
   approval thresholds for the shipped configuration.
