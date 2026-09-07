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
  viewChildren,
} from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';

import { UiStateService } from '../../core/ui-state.service';
import { ACCOUNT_TABS, AccountTab, normalizeTab } from './account.model';
import { AccountService } from './account.service';
import { PasskeysTab } from './passkeys-tab';
import { PasswordTab } from './password-tab';
import { ProfileTab } from './profile-tab';
import { SessionsTab } from './sessions-tab';
import { TwoFactorTab } from './two-factor-tab';

/**
 * The account page: one tab strip over five independent panels.
 *
 * The panels are mounted one at a time on purpose. Recovery codes and the TOTP
 * seed live in the two-factor panel's own state, so leaving the tab destroys
 * them rather than leaving a secret sitting in memory behind another panel.
 */
@Component({
  selector: 'app-account-page',
  imports: [ProfileTab, PasswordTab, TwoFactorTab, PasskeysTab, SessionsTab],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './account-page.html',
  styleUrl: './account-page.scss',
})
export class AccountPage {
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  private readonly ui = inject(UiStateService);
  private readonly account = inject(AccountService);

  /** Bound from `?tab=` by the router's component input binding. */
  readonly tab = input<string | undefined>(undefined);

  private readonly tabButtons = viewChildren<ElementRef<HTMLButtonElement>>('tabButton');
  private readonly selected = signal<AccountTab>('profile');

  protected readonly active = this.selected.asReadonly();

  protected readonly tabs = computed(() =>
    ACCOUNT_TABS.map((key) => ({
      key,
      label: LABELS[key],
      hint: this.hintFor(key),
      current: this.selected() === key,
    })),
  );

  constructor() {
    effect(() => {
      const fromUrl = normalizeTab(this.tab());
      untracked(() => this.selected.set(fromUrl));
    });

    // Both counts are on the tab strip, so both lists load with the page rather
    // than when their own panel is first opened. The profile comes with them
    // because a pending email change has to show on arrival, not only after the
    // request that started it.
    void this.ui.track('Loading account', async () => {
      await Promise.all([
        this.account.loadProfile(),
        this.account.loadSessions(),
        this.account.loadPasskeys(),
      ]);
    });
  }

  protected select(tab: AccountTab): void {
    this.selected.set(tab);
    void this.router.navigate([], {
      relativeTo: this.route,
      queryParams: { tab },
      queryParamsHandling: 'merge',
      replaceUrl: true,
    });
  }

  protected onTabKey(event: KeyboardEvent, index: number): void {
    const next = this.nextIndex(event.key, index);
    if (next === null) {
      return;
    }
    event.preventDefault();
    const tab = ACCOUNT_TABS[next];
    this.select(tab);
    this.tabButtons()[next]?.nativeElement.focus();
  }

  private nextIndex(key: string, index: number): number | null {
    const last = ACCOUNT_TABS.length - 1;
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

  private hintFor(tab: AccountTab): string {
    switch (tab) {
      case 'two-factor':
        return this.account.mfaEnabled() ? 'ON' : 'OFF';
      case 'passkeys':
        return String(this.account.passkeyCount());
      case 'sessions':
        return String(this.account.sessionCount());
      default:
        return '';
    }
  }
}

const LABELS: Record<AccountTab, string> = {
  profile: 'Profile',
  password: 'Password',
  'two-factor': 'Two-factor',
  passkeys: 'Passkeys',
  sessions: 'Sessions',
};
