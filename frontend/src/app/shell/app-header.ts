import { ChangeDetectionStrategy, Component, computed, inject, input, output, signal } from '@angular/core';
import { Router } from '@angular/router';

import { AuthService } from '../core/auth.service';
import { OrganizationContextService } from '../core/organization-context.service';
import { SearchService } from '../core/search.service';
import { TimeContextService } from '../core/time-context.service';

@Component({
  selector: 'app-header',
  imports: [],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './app-header.html',
  styleUrl: './app-header.scss',
})
export class AppHeader {
  readonly unread = input(0);
  readonly serviceHealthy = input<boolean | null>(null);
  readonly buildLabel = input('');
  readonly openNotifications = output<void>();

  private readonly router = inject(Router);
  protected readonly auth = inject(AuthService);
  protected readonly organizations = inject(OrganizationContextService);
  protected readonly time = inject(TimeContextService);
  protected readonly search = inject(SearchService);

  protected readonly orgMenuOpen = signal(false);
  protected readonly userMenuOpen = signal(false);

  protected readonly organization = this.organizations.selected;
  protected readonly regionCode = computed(() => (this.organization()?.cloud_region ?? '').toUpperCase().replace('_', '-'));
  protected readonly orgVerified = computed(() => this.organization()?.status === 'verified');

  protected readonly options = computed(() =>
    this.organizations.all().map((item) => ({
      id: item.id,
      name: item.name,
      verified: item.status === 'verified',
      meta: `${item.cloud_region.toUpperCase().replace('_', '-')} · ${item.status.toUpperCase()}${
        item.initial_snapshot_completed_at ? '' : ' · NO SNAPSHOT'
      }`,
      current: item.id === this.organization()?.id,
    })),
  );

  protected toggleOrgMenu(): void {
    this.orgMenuOpen.update((open) => !open);
    this.userMenuOpen.set(false);
  }

  protected toggleUserMenu(): void {
    this.userMenuOpen.update((open) => !open);
    this.orgMenuOpen.set(false);
  }

  protected closeMenus(): void {
    this.orgMenuOpen.set(false);
    this.userMenuOpen.set(false);
  }

  protected pick(id: string): void {
    this.organizations.select(id);
    this.closeMenus();
  }

  protected onSearch(value: string): void {
    this.search.setQuery(value);
  }

  protected async go(path: string): Promise<void> {
    this.closeMenus();
    await this.router.navigate([path]);
  }

  protected async signOut(): Promise<void> {
    this.closeMenus();
    await this.auth.logout();
    this.organizations.reset();
    await this.router.navigate(['/login']);
  }

  protected onSearchKey(event: KeyboardEvent): void {
    if (event.key === 'Enter') {
      void this.router.navigate(['/search'], { queryParams: { q: this.search.query() } });
    }
    if (event.key === 'Escape') {
      this.search.setQuery('');
    }
  }
}
