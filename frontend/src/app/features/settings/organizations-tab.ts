import { HttpErrorResponse } from '@angular/common/http';
import { ChangeDetectionStrategy, Component, computed, inject, output, signal } from '@angular/core';
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { firstValueFrom } from 'rxjs';

import { AuthService } from '../../core/auth.service';
import { formatCount, formatInstant } from '../../core/format';
import { OrganizationContextService } from '../../core/organization-context.service';
import {
  MIST_REGIONS,
  MistCloudRegion,
  Organization,
  regionLabel,
  SnapshotManifest,
} from '../../core/organization.model';
import { OrganizationService } from '../../core/organization.service';
import { Tone } from '../../core/tone';
import { copyToClipboard, type ConfirmRequest, type CronReveal, type SecretReveal } from './settings-page';

/** One "check for changes" preset and the cron expression it writes. */
export interface CronPreset {
  minutes: number;
  label: string;
  rate: string;
  cron: string;
}

/**
 * The schedule presets the card offers.
 *
 * Every preset lands at 02:00 UTC so a reconciliation never competes with the
 * working day of the organization it snapshots.
 */
export const CRON_PRESETS: readonly CronPreset[] = [
  { minutes: 720, label: 'every 12 hours', rate: 'twice a day', cron: '0 2,14 * * *' },
  { minutes: 1440, label: 'every day', rate: 'once a day', cron: '0 2 * * *' },
  { minutes: 10080, label: 'every week', rate: 'once a week', cron: '0 2 * * 0' },
  { minutes: 43200, label: 'every month', rate: 'once a month', cron: '0 2 1 * *' },
];

/** The preset a stored cron expression corresponds to, or null when custom. */
export function presetForCron(expression: string): CronPreset | null {
  const normalized = expression.trim().replace(/\s+/g, ' ');
  return CRON_PRESETS.find((preset) => preset.cron === normalized) ?? null;
}

/**
 * The next UTC instant a five-field cron expression fires, or null when the
 * expression is not one this evaluator understands.
 *
 * The card promises a next-run time, and a promise computed from the stored
 * expression is the only one that stays true when the expression is edited
 * outside these presets.
 */
export function nextCronRun(expression: string, from: Date = new Date()): Date | null {
  const fields = expression.trim().split(/\s+/);
  if (fields.length !== 5) {
    return null;
  }
  const minutes = parseCronField(fields[0], 0, 59);
  const hours = parseCronField(fields[1], 0, 23);
  const monthDays = parseCronField(fields[2], 1, 31);
  const months = parseCronField(fields[3], 1, 12);
  const weekDays = parseCronField(fields[4], 0, 7);
  if (!minutes || !hours || !monthDays || !months || !weekDays) {
    return null;
  }
  // Cron treats 7 and 0 as Sunday.
  const days = new Set(weekDays.map((day) => (day === 7 ? 0 : day)));
  const domRestricted = fields[2] !== '*';
  const dowRestricted = fields[4] !== '*';
  const startOfDay = Date.UTC(from.getUTCFullYear(), from.getUTCMonth(), from.getUTCDate());
  for (let offset = 0; offset <= 400; offset++) {
    const date = new Date(startOfDay + offset * 86_400_000);
    if (!months.includes(date.getUTCMonth() + 1)) {
      continue;
    }
    const byDate = monthDays.includes(date.getUTCDate());
    const byWeekday = days.has(date.getUTCDay());
    const matches = domRestricted && dowRestricted ? byDate || byWeekday : byDate && byWeekday;
    if (!matches) {
      continue;
    }
    for (const hour of hours) {
      for (const minute of minutes) {
        const candidate = Date.UTC(
          date.getUTCFullYear(),
          date.getUTCMonth(),
          date.getUTCDate(),
          hour,
          minute,
        );
        if (candidate > from.getTime()) {
          return new Date(candidate);
        }
      }
    }
  }
  return null;
}

function parseCronField(field: string, min: number, max: number): number[] | null {
  const values = new Set<number>();
  for (const part of field.split(',')) {
    const [range, stepText] = part.split('/');
    const step = stepText === undefined ? 1 : Number(stepText);
    if (!Number.isInteger(step) || step < 1) {
      return null;
    }
    let start = min;
    let end = max;
    if (range !== '*') {
      const bounds = range.split('-');
      start = Number(bounds[0]);
      end = bounds.length > 1 ? Number(bounds[1]) : start;
      if (bounds.length > 2 || !Number.isInteger(start) || !Number.isInteger(end)) {
        return null;
      }
      if (start < min || end > max || end < start) {
        return null;
      }
      if (stepText !== undefined) {
        end = bounds.length > 1 ? end : max;
      }
    }
    for (let value = start; value <= end; value += step) {
      values.add(value);
    }
  }
  return values.size === 0 ? null : [...values].sort((a, b) => a - b);
}

/**
 * The organizations panel.
 *
 * Each organization is one expandable card. Credentials and schedule sit on the
 * left, the webhook and its snapshot history on the right, so an operator can
 * see in one place why a change arrived late: a stale token, a slow schedule,
 * or a webhook that was never configured.
 */
@Component({
  selector: 'app-organizations-tab',
  imports: [ReactiveFormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './organizations-tab.html',
  styleUrl: './organizations-tab.scss',
})
export class OrganizationsTab {
  private readonly api = inject(OrganizationService);
  private readonly context = inject(OrganizationContextService);
  private readonly auth = inject(AuthService);

  readonly cronRequested = output<CronReveal>();
  readonly confirmRequested = output<ConfirmRequest>();
  readonly secretRevealed = output<SecretReveal>();

  protected readonly presets = CRON_PRESETS;
  protected readonly regions = MIST_REGIONS.map((region) => ({ value: region, label: regionLabel(region) }));

  protected readonly canManage = computed(() => {
    this.auth.user();
    return this.auth.can('administrator');
  });

  /**
   * Which card is open. Null means "not chosen yet", in which case the card for
   * the organization currently in scope opens — that is the one an
   * administrator arriving from the shell's organization menu came to see.
   */
  private readonly expandedId = signal<string | null>(null);
  private readonly collapsedByUser = signal(false);
  private readonly drafts = signal<Record<string, Draft>>({});
  private readonly snapshots = signal<Record<string, SnapshotManifest[]>>({});
  private readonly snapshotsLoaded = signal<Record<string, boolean>>({});
  private readonly tokenEditingId = signal<string | null>(null);

  protected readonly tokenDraft = signal('');
  protected readonly addOpen = signal(false);

  /**
   * Onboarding form.
   *
   * There is no name field: the organization's name is read from Mist with the
   * token, so a mistyped name cannot disagree with the cloud.
   */
  protected readonly addForm = new FormGroup({
    cloud_region: new FormControl<MistCloudRegion>('global_01', { nonNullable: true }),
    service_token: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
    reconciliation_cron: new FormControl('0 2 * * *', { nonNullable: true, validators: [Validators.required] }),
    configuration_retention_days: new FormControl(365, { nonNullable: true }),
    monitoring_retention_days: new FormControl(90, { nonNullable: true }),
    // A service token is a credential, so onboarding confirms who is asking.
    password: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
  });
  /** The password confirming a service-token replacement; never persisted. */
  protected readonly tokenPassword = signal('');
  protected readonly busy = signal('');
  protected readonly notice = signal('');
  protected readonly error = signal('');

  protected readonly cards = computed(() =>
    this.context.all().map((organization) => this.toCard(organization)),
  );

  protected readonly currentId = computed(() => this.context.selected()?.id ?? null);

  // ------------------------------------------------------------------ cards
  private toCard(organization: Organization) {
    const draft = this.draftFor(organization);
    const chosen = this.expandedId();
    const expanded =
      chosen === null && !this.collapsedByUser()
        ? organization.id === this.currentId()
        : chosen === organization.id;
    const preset = presetForCron(draft.cron);
    const next = nextCronRun(draft.cron);
    const history = this.snapshots()[organization.id] ?? [];
    const latest = history.find((item) => item.status === 'completed' || item.status === 'partial');
    return {
      organization,
      id: organization.id,
      name: organization.name,
      expanded,
      caret: expanded ? '▾' : '▸',
      status: organization.status.toUpperCase(),
      statusTone: statusTone(organization.status),
      isCurrent: organization.id === this.currentId(),
      region: regionLabel(organization.cloud_region),
      mistId: organization.mist_org_id,
      tokenSuffix: organization.service_token_set
        ? `•••• ${organization.service_token_last_four}`
        : 'Not set',
      verifiedAt: organization.credential_verified_at
        ? formatInstant(new Date(organization.credential_verified_at))
        : 'Never',
      credentialError: organization.credential_error,
      snapshotLabel: snapshotLabel(organization, latest),
      cron: draft.cron,
      presetLabel: preset?.label ?? 'a custom expression',
      reconSummary: preset
        ? `${sentenceCase(preset.label)} · runs ${preset.rate}${next ? ` · next run ${formatInstant(next)}` : ''}`
        : `Custom schedule ${draft.cron}${next ? ` · next run ${formatInstant(next)}` : ''}`,
      nextRunLabel: next ? formatInstant(next) : 'unknown — the expression could not be read',
      reconWarn:
        preset !== null && preset.minutes >= 10080
          ? 'At this interval a missed webhook could hide a change for days. Weekly or monthly suits archival snapshots, not day-to-day assurance.'
          : '',
      configurationRetention: draft.configurationRetention,
      monitoringRetention: draft.monitoringRetention,
      dirty:
        draft.cron !== organization.reconciliation_cron ||
        draft.configurationRetention !== organization.configuration_retention_days ||
        draft.monitoringRetention !== organization.monitoring_retention_days,
      webhookLabel: organization.webhook_secret_set
        ? `Configured · secret •••• ${organization.webhook_secret_last_four ?? '????'}`
        : 'Not configured — no secret has been generated',
      webhookConfigured: organization.webhook_secret_set,
      webhookLastReceived: organization.webhook_last_received_at
        ? formatInstant(new Date(organization.webhook_last_received_at))
        : 'never',
      endpoint: this.endpointFor(organization),
      tokenEditing: this.tokenEditingId() === organization.id,
      history: history.map((manifest) => this.toHistoryRow(manifest)),
      historyLoaded: this.snapshotsLoaded()[organization.id] === true,
    };
  }

  private toHistoryRow(manifest: SnapshotManifest) {
    const started = manifest.started_at ? new Date(manifest.started_at) : null;
    const completed = manifest.completed_at ? new Date(manifest.completed_at) : null;
    const seconds =
      started && completed ? (completed.getTime() - started.getTime()) / 1000 : null;
    return {
      id: manifest.id,
      at: formatInstant(new Date(manifest.created_at)),
      kind: KINDS[manifest.kind],
      objects: formatCount(manifest.discovered_objects),
      duration: seconds === null ? '—' : `${seconds.toFixed(1)}s`,
      status: STATUS_LABELS[manifest.status],
      tone: snapshotTone(manifest.status),
    };
  }

  /** The public URL Mist posts to, matching the backend's webhook route. */
  private endpointFor(organization: Organization): string {
    const origin = typeof location === 'undefined' ? '' : location.origin;
    return `${origin}/api/v1/webhooks/mist/${organization.id}`;
  }

  private draftFor(organization: Organization): Draft {
    return (
      this.drafts()[organization.id] ?? {
        cron: organization.reconciliation_cron,
        configurationRetention: organization.configuration_retention_days,
        monitoringRetention: organization.monitoring_retention_days,
      }
    );
  }

  private patchDraft(organization: Organization, patch: Partial<Draft>): void {
    const current = this.draftFor(organization);
    this.drafts.update((all) => ({ ...all, [organization.id]: { ...current, ...patch } }));
    this.notice.set('');
  }

  // --------------------------------------------------------------- onboarding
  protected openAdd(): void {
    this.addOpen.set(true);
    this.error.set('');
    this.notice.set('');
    this.addForm.reset({
      cloud_region: 'global_01',
      service_token: '',
      reconciliation_cron: '0 2 * * *',
      configuration_retention_days: 365,
      monitoring_retention_days: 90,
    });
  }

  protected closeAdd(): void {
    this.addOpen.set(false);
    // The token and the password exist only for the request that onboards the
    // organization, which this is not.
    this.addForm.controls.service_token.reset('');
    this.addForm.controls.password.reset('');
  }

  protected async add(): Promise<void> {
    if (this.addForm.invalid) {
      this.addForm.markAllAsTouched();
      return;
    }
    const value = this.addForm.getRawValue();
    await this.run('add', 'Organization onboarded.', async () => {
      const created = await firstValueFrom(
        this.api.create({
          cloud_region: value.cloud_region,
          service_token: value.service_token.trim(),
          reconciliation_cron: value.reconciliation_cron.trim(),
          configuration_retention_days: value.configuration_retention_days,
          monitoring_retention_days: value.monitoring_retention_days,
          password: value.password,
        }),
      );
      this.closeAdd();
      await this.context.load(true);
      this.expandedId.set(created.id);
      void this.loadSnapshots(created);
    });
    // Spent by the request whether or not it succeeded.
    this.addForm.controls.service_token.reset('');
    this.addForm.controls.password.reset('');
  }

  protected addCronLabel(): string {
    return presetForCron(this.addForm.controls.reconciliation_cron.value)?.label ?? 'a custom expression';
  }

  protected pickAddPreset(preset: CronPreset): void {
    this.addForm.controls.reconciliation_cron.setValue(preset.cron);
  }

  protected isAddPreset(preset: CronPreset): boolean {
    return this.addForm.controls.reconciliation_cron.value === preset.cron;
  }

  // --------------------------------------------------------------- expanding
  protected toggle(organization: Organization): void {
    const card = this.cards().find((item) => item.id === organization.id);
    const next = card?.expanded ? null : organization.id;
    this.collapsedByUser.set(next === null);
    this.expandedId.set(next);
    this.error.set('');
    this.notice.set('');
    if (next !== null && this.snapshotsLoaded()[organization.id] !== true) {
      void this.loadSnapshots(organization);
    }
  }

  private async loadSnapshots(organization: Organization): Promise<void> {
    if (!this.canManage()) {
      return;
    }
    try {
      const response = await firstValueFrom(this.api.snapshots(organization.id));
      this.snapshots.update((all) => ({ ...all, [organization.id]: response.items }));
    } catch {
      this.snapshots.update((all) => ({ ...all, [organization.id]: [] }));
    } finally {
      this.snapshotsLoaded.update((all) => ({ ...all, [organization.id]: true }));
    }
  }

  // ---------------------------------------------------------------- schedule
  protected pickPreset(organization: Organization, preset: CronPreset): void {
    this.patchDraft(organization, { cron: preset.cron });
  }

  protected isPreset(organization: Organization, preset: CronPreset): boolean {
    return this.draftFor(organization).cron === preset.cron;
  }

  protected setRetention(organization: Organization, field: RetentionField, event: Event): void {
    const value = Number((event.target as HTMLInputElement).value);
    if (!Number.isFinite(value)) {
      return;
    }
    const clamped = Math.min(3650, Math.max(1, Math.round(value)));
    this.patchDraft(organization, { [field]: clamped });
  }

  protected showCron(organization: Organization): void {
    const draft = this.draftFor(organization);
    const next = nextCronRun(draft.cron);
    this.cronRequested.emit({
      name: organization.name,
      preset: presetForCron(draft.cron)?.label ?? 'this custom schedule',
      expression: draft.cron,
      nextRun: next ? formatInstant(next) : 'unknown — the expression could not be read',
    });
  }

  // ----------------------------------------------------------------- actions
  protected async save(organization: Organization): Promise<void> {
    const draft = this.draftFor(organization);
    await this.run(`save-${organization.id}`, 'Settings saved.', async () => {
      const updated = await firstValueFrom(
        this.api.update(organization.id, {
          reconciliation_cron: draft.cron,
          configuration_retention_days: draft.configurationRetention,
          monitoring_retention_days: draft.monitoringRetention,
        }),
      );
      this.context.replace(updated);
      this.drafts.update((all) => {
        const { [organization.id]: _dropped, ...rest } = all;
        return rest;
      });
    });
  }

  protected async reverify(organization: Organization): Promise<void> {
    await this.run(`verify-${organization.id}`, 'Service token reverified.', async () => {
      this.context.replace(await firstValueFrom(this.api.verify(organization.id)));
    });
  }

  protected async runSnapshot(organization: Organization): Promise<void> {
    await this.run(`snapshot-${organization.id}`, 'Snapshot queued.', async () => {
      await firstValueFrom(this.api.triggerSnapshot(organization.id, 'manual'));
      this.snapshotsLoaded.update((all) => ({ ...all, [organization.id]: false }));
      await this.loadSnapshots(organization);
    });
  }

  protected startTokenEdit(organization: Organization): void {
    this.tokenEditingId.set(organization.id);
    // Neither field carries over from a previous edit, whether it was
    // abandoned or belonged to a different organization.
    this.tokenDraft.set('');
    this.tokenPassword.set('');
    this.error.set('');
    this.notice.set('');
  }

  protected cancelTokenEdit(): void {
    this.tokenEditingId.set(null);
    // The token and the password confirming it exist only for the request that
    // replaces the token, and that request did not happen.
    this.tokenDraft.set('');
    this.tokenPassword.set('');
  }

  protected onTokenInput(event: Event): void {
    this.tokenDraft.set((event.target as HTMLInputElement).value);
  }

  protected async replaceToken(organization: Organization): Promise<void> {
    const token = this.tokenDraft().trim();
    const password = this.tokenPassword();
    if (!token || !password) {
      return;
    }
    await this.run(`token-${organization.id}`, 'Service token replaced and verified.', async () => {
      this.context.replace(
        await firstValueFrom(this.api.replaceServiceToken(organization.id, token, password)),
      );
      this.cancelTokenEdit();
    });
    // Both are spent by the request and never outlive it.
    this.tokenDraft.set('');
    this.tokenPassword.set('');
  }

  protected setTokenPassword(event: Event): void {
    this.tokenPassword.set((event.target as HTMLInputElement).value);
  }

  protected requestRotate(organization: Organization): void {
    this.confirmRequested.emit({
      title: 'Rotate the webhook secret?',
      body: `Mist will reject events signed with the old secret the moment the new one is generated. Until you paste the new secret into the Mist webhook configuration, change events for ${organization.name} arrive only through scheduled reconciliation.`,
      detail: 'The new secret is displayed once and never again.',
      confirmLabel: 'Rotate secret',
      danger: true,
      requiresPassword: true,
      run: async (password: string) => {
        const rotated = await firstValueFrom(this.api.rotateWebhookSecret(organization.id, password));
        this.secretRevealed.emit({
          title: 'New webhook secret',
          body: `Copy this into the Mist webhook configuration for ${organization.name} now.`,
          value: rotated.secret,
          endpoint: rotated.endpoint,
        });
        try {
          this.context.replace(await firstValueFrom(this.api.get(organization.id)));
        } catch {
          // The secret is already on screen; a stale suffix is not worth losing it.
        }
      },
    });
  }

  protected switchScope(organization: Organization): void {
    this.context.select(organization.id);
    this.notice.set(`Scope switched to ${organization.name}.`);
  }

  protected async copyEndpoint(endpoint: string): Promise<void> {
    this.notice.set(await copyToClipboard(endpoint, 'Endpoint URL'));
  }

  protected isBusy(key: string): boolean {
    return this.busy() === key;
  }

  private async run(key: string, success: string, work: () => Promise<void>): Promise<void> {
    if (this.busy()) {
      return;
    }
    this.busy.set(key);
    this.error.set('');
    this.notice.set('');
    try {
      await work();
      this.notice.set(success);
    } catch (cause) {
      this.error.set(detailOf(cause));
    } finally {
      this.busy.set('');
    }
  }
}

type RetentionField = 'configurationRetention' | 'monitoringRetention';

interface Draft {
  cron: string;
  configurationRetention: number;
  monitoringRetention: number;
}

const KINDS: Record<SnapshotManifest['kind'], string> = {
  initial: 'Initial',
  reconciliation: 'Scheduled',
  manual: 'Manual',
};

const STATUS_LABELS: Record<SnapshotManifest['status'], string> = {
  pending: 'PENDING',
  running: 'RUNNING',
  completed: 'OK',
  partial: 'PARTIAL',
  failed: 'FAILED',
};

function snapshotTone(status: SnapshotManifest['status']): Tone {
  if (status === 'completed') {
    return 'ok';
  }
  if (status === 'failed') {
    return 'crit';
  }
  return 'warn';
}

function statusTone(status: Organization['status']): Tone {
  switch (status) {
    case 'verified':
      return 'ok';
    case 'error':
      return 'crit';
    case 'disabled':
      return 'none';
    default:
      return 'warn';
  }
}

function snapshotLabel(organization: Organization, latest: SnapshotManifest | undefined): string {
  if (latest) {
    const at = formatInstant(new Date(latest.completed_at ?? latest.created_at));
    return `${at} · ${formatCount(latest.discovered_objects)} objects`;
  }
  return organization.initial_snapshot_completed_at
    ? `Initial snapshot ${formatInstant(new Date(organization.initial_snapshot_completed_at))}`
    : 'No snapshot yet';
}

function sentenceCase(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function detailOf(cause: unknown): string {
  if (cause instanceof HttpErrorResponse) {
    const detail: unknown = (cause.error as { detail?: unknown } | null)?.detail;
    if (typeof detail === 'string') {
      return detail;
    }
    if (cause.status === 403) {
      return 'Your role does not allow this change.';
    }
  }
  return 'The request could not be completed.';
}
