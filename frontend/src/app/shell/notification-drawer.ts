import {
  afterNextRender,
  ChangeDetectionStrategy,
  Component,
  computed,
  DestroyRef,
  ElementRef,
  inject,
  output,
  viewChild,
} from '@angular/core';
import { Router } from '@angular/router';

import { rememberFocus, restoreFocus, trapTab } from '../core/focus';
import { formatTime } from '../core/format';
import { AppNotification, NotificationService } from '../core/notification.service';
import { OrganizationContextService } from '../core/organization-context.service';

const ROUTES: Record<string, string> = {
  overview: '/',
  changes: '/changes',
  history: '/history',
  restore: '/restore',
  impact: '/impact',
  settings: '/settings',
};

@Component({
  selector: 'app-notification-drawer',
  imports: [],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './notification-drawer.html',
  styleUrl: './notification-drawer.scss',
})
export class NotificationDrawer {
  readonly closed = output<void>();

  private readonly router = inject(Router);
  private readonly organizations = inject(OrganizationContextService);
  protected readonly notifications = inject(NotificationService);

  private readonly panel = viewChild.required<ElementRef<HTMLElement>>('panel');
  /** Whatever had focus when the drawer opened — the bell, normally. */
  private readonly opener = rememberFocus();

  constructor() {
    // The drawer declares itself modal, so it behaves as one: focus moves in
    // when it opens, and goes back to the opener when it closes.
    afterNextRender(() => this.panel().nativeElement.focus());
    inject(DestroyRef).onDestroy(() => restoreFocus(this.opener));
  }

  protected readonly rows = computed(() =>
    this.notifications.items().map((item) => ({
      ...item,
      at: formatTime(new Date(item.created_at)),
      tone: item.severity,
      unread: item.read_at === null,
    })),
  );

  protected async open(notification: AppNotification): Promise<void> {
    const organizationId = this.organizations.selected()?.id;
    if (organizationId && notification.read_at === null) {
      await this.notifications.markRead(organizationId, notification.id);
    }
    this.closed.emit();
    await this.router.navigate([ROUTES[notification.target] ?? '/'], {
      queryParams: notification.target_params,
    });
  }

  protected async markAllRead(): Promise<void> {
    const organizationId = this.organizations.selected()?.id;
    if (organizationId) {
      await this.notifications.markAllRead(organizationId);
    }
  }

  protected onKey(event: KeyboardEvent): void {
    trapTab(event, this.panel().nativeElement);
    if (event.key === 'Escape') {
      this.closed.emit();
    }
  }
}
