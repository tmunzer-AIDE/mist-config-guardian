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

  /**
   * The organization this state belongs to.
   *
   * Every notification here — the drawer list, the badge, an optimistic
   * mark-read — is one organization's. Sequencing each kind of read on its own
   * is not enough: a mark-read answering after a switch would still edit the
   * new organization's list, and a list answer carrying a count would race the
   * count endpoint. One owner decides whose state this is, and the per-read
   * sequences order answers within it.
   */
  private owner: string | null = null;
  private listRequest = 0;
  private countRequest = 0;

  /** Take ownership for an organization, dropping anything the previous one left. */
  private claim(organizationId: string): void {
    if (this.owner === organizationId) {
      return;
    }
    this.owner = organizationId;
    this.listRequest += 1;
    this.countRequest += 1;
    this.items.set([]);
    this.unread.set(0);
    this.loading.set(false);
  }

  private owns(organizationId: string): boolean {
    return this.owner === organizationId;
  }

  async load(organizationId: string, unreadOnly = false): Promise<void> {
    this.claim(organizationId);
    const request = ++this.listRequest;
    // The list answer carries a count, so it takes a number in that sequence
    // too: the badge has one order however it was read.
    const counted = ++this.countRequest;
    this.loading.set(true);
    try {
      const params = new HttpParams().set('unread_only', unreadOnly).set('limit', 50);
      const response = await firstValueFrom(
        this.http.get<NotificationList>(orgPath(organizationId, '/notifications'), { params }),
      );
      if (this.owns(organizationId) && request === this.listRequest) {
        this.items.set(response.items);
      }
      if (this.owns(organizationId) && counted === this.countRequest) {
        this.unread.set(response.unread);
      }
    } finally {
      if (this.owns(organizationId) && request === this.listRequest) {
        this.loading.set(false);
      }
    }
  }

  async refreshUnread(organizationId: string): Promise<void> {
    this.claim(organizationId);
    const request = ++this.countRequest;
    const response = await firstValueFrom(
      this.http.get<{ unread: number }>(orgPath(organizationId, '/notifications/unread-count')),
    );
    if (this.owns(organizationId) && request === this.countRequest) {
      this.unread.set(response.unread);
    }
  }

  async markRead(organizationId: string, id: string): Promise<void> {
    await firstValueFrom(this.http.post(orgPath(organizationId, `/notifications/${id}/read`), {}));
    // The acknowledgement is recorded server-side regardless; the optimistic
    // edit applies only while this organization still owns what is on screen.
    if (!this.owns(organizationId)) {
      return;
    }
    this.items.update((list) =>
      list.map((item) => (item.id === id ? { ...item, read_at: new Date().toISOString() } : item)),
    );
    this.unread.update((value) => Math.max(0, value - 1));
  }

  async markAllRead(organizationId: string): Promise<void> {
    await firstValueFrom(this.http.post(orgPath(organizationId, '/notifications/read-all'), {}));
    if (!this.owns(organizationId)) {
      return;
    }
    const now = new Date().toISOString();
    this.items.update((list) => list.map((item) => ({ ...item, read_at: item.read_at ?? now })));
    this.unread.set(0);
  }

  reset(): void {
    this.owner = null;
    this.listRequest += 1;
    this.countRequest += 1;
    this.items.set([]);
    this.unread.set(0);
    this.loading.set(false);
  }
}
