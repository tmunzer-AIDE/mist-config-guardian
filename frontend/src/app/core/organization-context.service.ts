import { computed, inject, Injectable, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';

import { Organization } from './organization.model';
import { OrganizationService } from './organization.service';

const SELECTED_KEY = 'mist-config-guardian.organization';

/**
 * The application-wide organization scope.
 *
 * Every scoped page reads `selectedId()`; changing the scope bumps `revision()`
 * so pages can reload without re-subscribing to router events.
 */
@Injectable({ providedIn: 'root' })
export class OrganizationContextService {
  private readonly organizations = inject(OrganizationService);

  private readonly items = signal<Organization[]>([]);
  private readonly selectedIdState = signal<string | null>(readStoredId());
  private readonly loadedState = signal(false);
  private readonly revisionState = signal(0);

  readonly all = this.items.asReadonly();
  readonly loaded = this.loadedState.asReadonly();
  readonly revision = this.revisionState.asReadonly();
  readonly selectedId = this.selectedIdState.asReadonly();

  readonly selected = computed<Organization | null>(() => {
    const id = this.selectedIdState();
    const list = this.items();
    return list.find((item) => item.id === id) ?? list[0] ?? null;
  });

  /** True once organizations were fetched and none exist. */
  readonly isEmpty = computed(() => this.loadedState() && this.items().length === 0);

  /** Load the organization list once per session, or again after onboarding. */
  async load(force = false): Promise<void> {
    if (this.loadedState() && !force) {
      return;
    }
    const response = await firstValueFrom(this.organizations.list());
    this.items.set(response.items);
    this.loadedState.set(true);
    const current = this.selectedIdState();
    if (!current || !response.items.some((item) => item.id === current)) {
      this.select(response.items[0]?.id ?? null, false);
    }
  }

  /** Replace one organization in place after an update, keeping list order. */
  replace(organization: Organization): void {
    this.items.update((list) => list.map((item) => (item.id === organization.id ? organization : item)));
  }

  select(id: string | null, notify = true): void {
    if (id === this.selectedIdState()) {
      return;
    }
    this.selectedIdState.set(id);
    try {
      if (id) {
        localStorage.setItem(SELECTED_KEY, id);
      } else {
        localStorage.removeItem(SELECTED_KEY);
      }
    } catch {
      // Storage can be unavailable in private windows; selection still applies.
    }
    if (notify) {
      this.revisionState.update((value) => value + 1);
    }
  }

  /** Forget cached state on sign-out so the next user starts clean. */
  reset(): void {
    this.items.set([]);
    this.loadedState.set(false);
    this.selectedIdState.set(null);
  }
}

function readStoredId(): string | null {
  try {
    return localStorage.getItem(SELECTED_KEY);
  } catch {
    return null;
  }
}
