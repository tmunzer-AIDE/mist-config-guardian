import { ChangeDetectionStrategy, Component, computed, inject, output } from '@angular/core';
import { Router } from '@angular/router';

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
    if (event.key === 'Escape') {
      this.closed.emit();
    }
  }
}
