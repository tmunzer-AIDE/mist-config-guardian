import {
  ChangeDetectionStrategy,
  Component,
  computed,
  effect,
  ElementRef,
  inject,
  input,
  signal,
  untracked,
  viewChild,
  viewChildren,
} from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';

import { AuthService } from '../../core/auth.service';
import { OrganizationContextService } from '../../core/organization-context.service';
import { SystemHealthService } from '../../core/system-health.service';
import { UiStateService } from '../../core/ui-state.service';
import { AiSettingsService } from './ai-settings.service';
import { AiTab } from './ai-tab';
import { HealthTab } from './health-tab';
import { OrganizationsTab } from './organizations-tab';
import { UsersService } from './users.service';
import { UsersTab } from './users-tab';

export type SettingsTab = 'organizations' | 'users' | 'ai' | 'health';

export const SETTINGS_TABS: readonly SettingsTab[] = ['organizations', 'users', 'ai', 'health'];

const LABELS: Record<SettingsTab, string> = {
  organizations: 'Organizations',
  users: 'Users and roles',
  ai: 'AI Assist',
  health: 'Service health',
};

// The shell links to /settings/health and /settings/organizations, and the
// overview links to ?tab=organizations, so both spellings resolve here. The
// aliases also cover the shorter names the prototype used internally.
const ALIASES: readonly (readonly [string, SettingsTab])[] = [
  ['organizations', 'organizations'],
  ['organization', 'organizations'],
  ['orgs', 'organizations'],
  ['org', 'organizations'],
  ['users', 'users'],
  ['users-and-roles', 'users'],
  ['roles', 'users'],
  ['accounts', 'users'],
  ['ai', 'ai'],
  ['ai-assist', 'ai'],
  ['assist', 'ai'],
  ['health', 'health'],
  ['service-health', 'health'],
];

/** Resolve a tab name from a query parameter or path segment, or null. */
export function matchSettingsTab(value: string | null | undefined): SettingsTab | null {
  if (!value) {
    return null;
  }
  const needle = value.trim().toLowerCase();
  return ALIASES.find(([alias]) => alias === needle)?.[1] ?? null;
}

/** Read a tab from an unmatched trailing path segment such as `/settings/health`. */
export function settingsTabFromUrl(url: string): SettingsTab | null {
  const path = url.split('?')[0].split('#')[0];
  const segments = path.split('/').filter(Boolean);
  const last = segments[segments.length - 1];
  return last === 'settings' ? null : matchSettingsTab(last);
}

/** The tab a URL selects, defaulting to organizations. */
export function resolveSettingsTab(param: string | undefined, url: string): SettingsTab {
  return matchSettingsTab(param) ?? settingsTabFromUrl(url) ?? 'organizations';
}

/** A destructive action awaiting confirmation in the shared dialog. */
export interface ConfirmRequest {
  title: string;
  body: string;
  detail?: string;
  confirmLabel: string;
  danger: boolean;
  /** True when the action changes a credential and must confirm who is asking. */
  requiresPassword?: boolean;
  run: (password: string) => Promise<void>;
}

/** A value the API returns exactly once and will never show again. */
export interface SecretReveal {
  title: string;
  body: string;
  value: string;
  endpoint?: string;
}

/** The cron expression behind a schedule preset. */
export interface CronReveal {
  name: string;
  preset: string;
  expression: string;
  nextRun: string;
}

/**
 * The settings page: one tab strip over four independent panels, plus the
 * three dialogs the panels share.
 *
 * The dialogs live here rather than in the panels because the one-time secret
 * must outlive the click that produced it without being stored anywhere, and
 * because a confirmation is requested by both the organizations and the users
 * panel. Panels raise a request; this component owns focus and dismissal.
 */
@Component({
  selector: 'app-settings-page',
  imports: [OrganizationsTab, UsersTab, AiTab, HealthTab],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './settings-page.html',
  styleUrl: './settings-page.scss',
})
export class SettingsPage {
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  private readonly ui = inject(UiStateService);
  private readonly auth = inject(AuthService);
  private readonly organizations = inject(OrganizationContextService);
  private readonly users = inject(UsersService);
  private readonly ai = inject(AiSettingsService);
  private readonly systemHealth = inject(SystemHealthService);

  /** Bound from `?tab=` (or a `:tab` segment) by component input binding. */
  readonly tab = input<string | undefined>(undefined);

  private readonly tabButtons = viewChildren<ElementRef<HTMLButtonElement>>('tabButton');
  private readonly dialogBody = viewChild<ElementRef<HTMLElement>>('dialogBody');
  private readonly selected = signal<SettingsTab>('organizations');

  protected readonly active = this.selected.asReadonly();
  protected readonly isAdministrator = computed(() => {
    // Read the user signal so the gate re-evaluates when the session resolves.
    this.auth.user();
    return this.auth.can('administrator');
  });

  protected readonly cron = signal<CronReveal | null>(null);
  protected readonly confirm = signal<ConfirmRequest | null>(null);
  protected readonly secret = signal<SecretReveal | null>(null);
  protected readonly confirmBusy = signal(false);
  /** The password a credential-changing confirmation asks for; never persisted. */
  protected readonly confirmPassword = signal('');
  protected readonly copyNotice = signal('');

  private returnFocus: HTMLElement | null = null;

  protected readonly tabs = computed(() =>
    SETTINGS_TABS.map((key) => ({
      key,
      label: LABELS[key],
      hint: this.hintFor(key),
      current: this.selected() === key,
    })),
  );

  constructor() {
    effect(() => {
      const tab = resolveSettingsTab(this.tab(), this.router.url);
      untracked(() => this.selected.set(tab));
    });

    // Every tab strip hint is a count, so the counts load with the page. The
    // users and AI endpoints are administrator-only; a viewer never calls them
    // and sees a read-only panel instead of a 403 banner.
    void this.ui.track('Loading settings', async () => {
      await this.systemHealth.load();
      if (!this.auth.can('administrator')) {
        return;
      }
      await Promise.all([
        this.organizations.load(true),
        this.users.load({ limit: 200 }),
        this.ai.load(),
      ]);
    });

    effect(() => {
      const host = this.dialogBody()?.nativeElement;
      if (host) {
        untracked(() => focusFirst(host));
      } else {
        untracked(() => this.restoreFocus());
      }
    });
  }

  // ------------------------------------------------------------------- tabs
  protected select(tab: SettingsTab): void {
    this.selected.set(tab);
    // Absolute, so a page reached by its path form (`/settings/<tab>`) does not
    // keep that segment: with both present the path wins on reload, and the
    // page would come back on a different tab than the one shown.
    void this.router.navigate(['/settings'], { queryParams: { tab }, replaceUrl: true });
  }

  protected onTabKey(event: KeyboardEvent, index: number): void {
    const next = nextIndex(event.key, index, SETTINGS_TABS.length);
    if (next === null) {
      return;
    }
    event.preventDefault();
    this.select(SETTINGS_TABS[next]);
    this.tabButtons()[next]?.nativeElement.focus();
  }

  // ---------------------------------------------------------------- dialogs
  protected openCron(request: CronReveal): void {
    this.beforeOpen();
    this.cron.set(request);
  }

  protected openConfirm(request: ConfirmRequest): void {
    this.beforeOpen();
    this.confirm.set(request);
  }

  protected openSecret(request: SecretReveal): void {
    this.beforeOpen();
    this.secret.set(request);
  }

  protected closeDialogs(): void {
    this.cron.set(null);
    this.confirm.set(null);
    // Dropping the reference is the only place the one-time secret is held.
    this.secret.set(null);
    this.confirmBusy.set(false);
    this.confirmPassword.set('');
    this.copyNotice.set('');
  }

  protected async runConfirmed(): Promise<void> {
    const request = this.confirm();
    if (!request || this.confirmBusy()) {
      return;
    }
    const password = this.confirmPassword();
    if (request.requiresPassword && !password) {
      return;
    }
    this.confirmBusy.set(true);
    try {
      await request.run(password);
      // A run that opened a dialog of its own — a rotated webhook secret is
      // shown exactly once — has already cleared this confirmation through
      // beforeOpen. Closing again here would discard the value it just put on
      // screen, which is the only time the secret is ever displayed.
      if (this.confirm() === request) {
        this.closeDialogs();
      }
    } finally {
      // The password is spent by the request and never outlives it.
      this.confirmPassword.set('');
      this.confirmBusy.set(false);
    }
  }

  protected setConfirmPassword(event: Event): void {
    this.confirmPassword.set((event.target as HTMLInputElement).value);
  }

  /**
   * Keep Tab inside the open dialog and let Escape dismiss it.
   *
   * A dialog that leaks focus behind the scrim leaves a keyboard user typing
   * into a page they cannot see, so the cycle wraps explicitly rather than
   * relying on DOM order.
   */
  protected onDialogKey(event: KeyboardEvent): void {
    if (event.key === 'Escape') {
      event.preventDefault();
      event.stopPropagation();
      this.closeDialogs();
      return;
    }
    if (event.key !== 'Tab') {
      return;
    }
    const host = this.dialogBody()?.nativeElement;
    if (!host) {
      return;
    }
    const focusable = focusableIn(host);
    if (focusable.length === 0) {
      return;
    }
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    const current = document.activeElement;
    if (event.shiftKey && (current === first || current === host)) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && current === last) {
      event.preventDefault();
      first.focus();
    }
  }

  protected async copy(value: string, label: string): Promise<void> {
    this.copyNotice.set(await copyToClipboard(value, label));
  }

  private beforeOpen(): void {
    this.closeDialogs();
    this.returnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  }

  private restoreFocus(): void {
    const target = this.returnFocus;
    this.returnFocus = null;
    if (target?.isConnected) {
      target.focus();
    }
  }

  private hintFor(tab: SettingsTab): string {
    switch (tab) {
      case 'organizations': {
        const count = this.organizations.all().length;
        return count === 0 ? '' : `${count} onboarded`;
      }
      case 'users': {
        const total = this.users.total();
        return total === 0 ? '' : `${total} account${total === 1 ? '' : 's'}`;
      }
      case 'ai': {
        const settings = this.ai.settings();
        return settings === null ? '' : settings.enabled ? 'Enabled' : 'Disabled';
      }
      case 'health': {
        const health = this.systemHealth.health();
        if (health === null) {
          return '';
        }
        const degraded = health.components.filter((item) => item.status !== 'ok').length;
        return degraded === 0 ? 'All healthy' : `${degraded} degraded`;
      }
    }
  }
}

/** The index a roving-tabindex arrow key moves to, or null for other keys. */
export function nextIndex(key: string, index: number, length: number): number | null {
  const last = length - 1;
  switch (key) {
    case 'ArrowRight':
    case 'ArrowDown':
      return index === last ? 0 : index + 1;
    case 'ArrowLeft':
    case 'ArrowUp':
      return index === 0 ? last : index - 1;
    case 'Home':
      return 0;
    case 'End':
      return last;
    default:
      return null;
  }
}

const FOCUSABLE =
  'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';

// Every control in these dialogs is added and removed with @if rather than
// hidden, so anything the selector matches is genuinely reachable.
function focusableIn(host: HTMLElement): HTMLElement[] {
  return Array.from(host.querySelectorAll<HTMLElement>(FOCUSABLE));
}

function focusFirst(host: HTMLElement): void {
  const focusable = focusableIn(host);
  (focusable[0] ?? host).focus();
}

/**
 * Copy through the async Clipboard API.
 *
 * There is no `document.execCommand` fallback on purpose: it needs the value
 * in a DOM node, and these values are webhook secrets.
 */
export async function copyToClipboard(value: string, label: string): Promise<string> {
  if (!navigator.clipboard?.writeText) {
    return `${label} could not be copied — this browser blocks clipboard access. Select the value and copy it manually.`;
  }
  try {
    await navigator.clipboard.writeText(value);
    return `${label} copied.`;
  } catch {
    return `${label} could not be copied — the browser denied clipboard permission. Select the value and copy it manually.`;
  }
}
