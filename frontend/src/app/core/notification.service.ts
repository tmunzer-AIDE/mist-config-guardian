import { HttpClient, HttpParams } from '@angular/common/http';
import { inject, Injectable, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';

import { orgPath } from './api';

export type NotificationSeverity = 'crit' | 'warn' | 'info' | 'ok';
export type NotificationTarget = 'overview' | 'changes' | 'history' | 'restore' | 'impact' | 'settings';

export interface AppNotification {
  id: string;
  kind: string;
  severity: NotificationSeverity;
  title: string;
  body: string;
  target: NotificationTarget;
  target_params: Record<string, string>;
  mandatory: boolean;
  read_at: string | null;
  created_at: string;
}

interface NotificationList {
  items: AppNotification[];
  total: number;
  unread: number;
}

/** In-application notification feed backing the header bell and drawer. */
@Injectable({ providedIn: 'root' })
export class NotificationService {
  private readonly http = inject(HttpClient);

  readonly items = signal<AppNotification[]>([]);
  readonly unread = signal(0);
  readonly loading = signal(false);

  async load(organizationId: string, unreadOnly = false): Promise<void> {
    this.loading.set(true);
    try {
      const params = new HttpParams().set('unread_only', unreadOnly).set('limit', 50);
      const response = await firstValueFrom(
        this.http.get<NotificationList>(orgPath(organizationId, '/notifications'), { params }),
      );
      this.items.set(response.items);
      this.unread.set(response.unread);
    } finally {
      this.loading.set(false);
    }
  }

  async refreshUnread(organizationId: string): Promise<void> {
    const response = await firstValueFrom(
      this.http.get<{ unread: number }>(orgPath(organizationId, '/notifications/unread-count')),
    );
    this.unread.set(response.unread);
  }

  async markRead(organizationId: string, id: string): Promise<void> {
    await firstValueFrom(this.http.post(orgPath(organizationId, `/notifications/${id}/read`), {}));
    this.items.update((list) =>
      list.map((item) => (item.id === id ? { ...item, read_at: new Date().toISOString() } : item)),
    );
    this.unread.update((value) => Math.max(0, value - 1));
  }

  async markAllRead(organizationId: string): Promise<void> {
    await firstValueFrom(this.http.post(orgPath(organizationId, '/notifications/read-all'), {}));
    const now = new Date().toISOString();
    this.items.update((list) => list.map((item) => ({ ...item, read_at: item.read_at ?? now })));
    this.unread.set(0);
  }

  reset(): void {
    this.items.set([]);
    this.unread.set(0);
  }
}
