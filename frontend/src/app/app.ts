import { ChangeDetectionStrategy, Component, computed, effect, inject, signal, untracked } from '@angular/core';
import { NavigationEnd, Router, RouterOutlet } from '@angular/router';
import { filter } from 'rxjs';

import { AuthService } from './core/auth.service';
import { formatDuration, formatInstant } from './core/format';
import { NotificationService } from './core/notification.service';
import { OrganizationContextService } from './core/organization-context.service';
import { OverviewService } from './core/overview.service';
import { SystemHealthService } from './core/system-health.service';
import { TimeContextService } from './core/time-context.service';
import { TimelineService } from './core/timeline.service';
import { UiStateService } from './core/ui-state.service';
import { AppHeader } from './shell/app-header';
import { AppSidebar } from './shell/app-sidebar';
import { AppTimeBar } from './shell/app-time-bar';
import { NotificationDrawer } from './shell/notification-drawer';

/** Pages that participate in point-in-time navigation. */
const TIME_BAR_ROUTES = ['/', '/changes', '/history', '/impact'];

@Component({
  selector: 'app-root',
  imports: [RouterOutlet, AppSidebar, AppHeader, AppTimeBar, NotificationDrawer],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './app.html',
  styleUrl: './app.scss',
})
export class App {
  protected readonly auth = inject(AuthService);
  protected readonly ui = inject(UiStateService);
  protected readonly time = inject(TimeContextService);
  protected readonly organizations = inject(OrganizationContextService);
  protected readonly notifications = inject(NotificationService);
  protected readonly overview = inject(OverviewService);
  protected readonly health = inject(SystemHealthService);
  private readonly timeline = inject(TimelineService);
  private readonly router = inject(Router);

  protected readonly drawerOpen = signal(false);
  private readonly currentUrl = signal(this.router.url);

  protected readonly buildLabel = computed(() => {
    const version = this.health.version();
    return version ? `v${version}` : '';
  });

  protected readonly chrome = computed(() => this.auth.isAuthenticated() && !this.currentUrl().startsWith('/login'));

  protected readonly showTimeBar = computed(() => {
    const url = this.currentUrl().split('?')[0];
    return this.chrome() && TIME_BAR_ROUTES.some((route) => (route === '/' ? url === '/' : url.startsWith(route)));
  });

  protected readonly asOfLabel = computed(() => {
    const asOf = this.time.asOf();
    return asOf ? formatInstant(asOf) : '';
  });

  protected readonly pastDelta = computed(() => {
    const asOf = this.time.asOf();
    return asOf ? formatDuration(asOf) : '';
  });

  protected readonly skeletons = [96, 132, 72, 72];

  constructor() {
    this.router.events.pipe(filter((event) => event instanceof NavigationEnd)).subscribe((event) => {
      this.currentUrl.set(event.urlAfterRedirects);
    });

    void this.health.loadVersion();

    // Load the organization list once the user is known, then keep the shell's
    // scope-derived data (badges, notifications, timeline) in step with it.
    effect(() => {
      if (!this.auth.isAuthenticated()) {
        return;
      }
      void untracked(() => this.organizations.load());
    });

    effect(() => {
      const organizationId = this.organizations.selected()?.id;
      const range = this.time.range();
      if (!organizationId) {
        return;
      }
      void untracked(async () => {
        await Promise.allSettled([
          this.notifications.refreshUnread(organizationId),
          this.timeline.load(organizationId, range),
          this.overview.loadBadges(organizationId),
          this.health.load(),
        ]);
      });
    });
  }

  protected async openDrawer(): Promise<void> {
    this.drawerOpen.set(true);
    const organizationId = this.organizations.selected()?.id;
    if (organizationId) {
      await this.notifications.load(organizationId);
    }
  }

  protected returnToNow(): void {
    this.time.returnToNow();
  }
}
