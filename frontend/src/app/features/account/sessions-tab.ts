import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';

import { formatInstant } from '../../core/format';
import { AccountSession } from './account.model';
import { AccountService, detailOf } from './account.service';

@Component({
  selector: 'app-sessions-tab',
  imports: [],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './sessions-tab.html',
  styleUrl: './sessions-tab.scss',
})
export class SessionsTab {
  private readonly account = inject(AccountService);

  protected readonly busyId = signal('');
  protected readonly revokingOthers = signal(false);
  protected readonly error = signal('');
  protected readonly notice = signal('');

  protected readonly rows = computed(() =>
    this.account.sessions().map((session) => this.toRow(session)),
  );

  /** Nothing to sign out of elsewhere when this is the only live session. */
  protected readonly hasOthers = computed(() =>
    this.account.sessions().some((session) => !session.current),
  );

  protected async revoke(id: string, label: string): Promise<void> {
    if (this.busyId()) {
      return;
    }
    this.busyId.set(id);
    this.error.set('');
    try {
      await this.account.revokeSession(id);
      this.notice.set(`Signed out ${label}.`);
    } catch (cause) {
      this.error.set(detailOf(cause));
    } finally {
      this.busyId.set('');
    }
  }

  protected async revokeOthers(): Promise<void> {
    if (this.revokingOthers()) {
      return;
    }
    this.revokingOthers.set(true);
    this.error.set('');
    try {
      const count = await this.account.revokeOtherSessions();
      this.notice.set(
        count === 0
          ? 'There were no other sessions to sign out.'
          : `Signed out ${count} other session${count === 1 ? '' : 's'}.`,
      );
    } catch (cause) {
      this.error.set(detailOf(cause));
    } finally {
      this.revokingOthers.set(false);
    }
  }

  private toRow(session: AccountSession) {
    const clock = this.account.clock();
    const where = session.location ?? session.ip_address ?? 'Unknown location';
    const when = session.current
      ? 'ACTIVE NOW'
      : formatInstant(new Date(session.last_seen_at), clock);
    return {
      id: session.id,
      label: session.label,
      current: session.current,
      meta: `${where.toUpperCase()} · ${when}`,
    };
  }
}
