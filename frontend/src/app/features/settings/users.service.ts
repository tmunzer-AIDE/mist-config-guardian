import { HttpClient, HttpParams } from '@angular/common/http';
import { inject, Injectable, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';

import { API_ROOT } from '../../core/api';
import { UserRole } from '../../core/auth.service';

export type ManagedUserStatus = 'invited' | 'active' | 'deactivated';

/** Administrative view of one local account. Never carries credential material. */
export interface ManagedUser {
  id: string;
  email: string;
  display_name: string;
  role: UserRole;
  status: ManagedUserStatus;
  is_active: boolean;
  mfa_enabled: boolean;
  invitation_expires_at?: string | null;
  last_login_at: string | null;
  created_at: string;
}

export interface ManagedUserList {
  items: ManagedUser[];
  total: number;
}

export interface UserInviteRequest {
  email: string;
  display_name: string;
  role: UserRole;
}

/**
 * The invitation token is returned outside production only, because this
 * deployment has no mail transport. It is shown once and never stored.
 */
export interface UserInviteResult {
  user: ManagedUser;
  invitation_expires_at: string | null;
  invitation_token: string | null;
  delivery: string;
}

export interface UserFilters {
  role?: UserRole;
  status?: ManagedUserStatus;
  q?: string;
  skip?: number;
  limit?: number;
}

/**
 * Local account administration.
 *
 * Every endpoint is administrator-only; callers gate on `AuthService.can`
 * rather than letting a viewer provoke a 403.
 */
@Injectable({ providedIn: 'root' })
export class UsersService {
  private readonly http = inject(HttpClient);

  private readonly itemsState = signal<ManagedUser[]>([]);
  private readonly totalState = signal(0);
  private readonly loadedState = signal(false);

  readonly items = this.itemsState.asReadonly();
  readonly total = this.totalState.asReadonly();
  readonly loaded = this.loadedState.asReadonly();

  async load(filters: UserFilters = {}): Promise<void> {
    let params = new HttpParams();
    if (filters.role) {
      params = params.set('role', filters.role);
    }
    if (filters.status) {
      params = params.set('status', filters.status);
    }
    if (filters.q) {
      params = params.set('q', filters.q);
    }
    if (filters.skip !== undefined) {
      params = params.set('skip', String(filters.skip));
    }
    if (filters.limit !== undefined) {
      params = params.set('limit', String(filters.limit));
    }
    const response = await firstValueFrom(this.http.get<ManagedUserList>(`${API_ROOT}/users`, { params }));
    this.itemsState.set(response.items);
    this.totalState.set(response.total);
    this.loadedState.set(true);
  }

  async invite(request: UserInviteRequest): Promise<UserInviteResult> {
    const result = await firstValueFrom(this.http.post<UserInviteResult>(`${API_ROOT}/users`, request));
    this.itemsState.update((list) => [...list, result.user]);
    this.totalState.update((value) => value + 1);
    return result;
  }

  async resendInvitation(id: string): Promise<UserInviteResult> {
    const result = await firstValueFrom(
      this.http.post<UserInviteResult>(`${API_ROOT}/users/${id}/resend-invitation`, {}),
    );
    this.replace(result.user);
    return result;
  }

  async update(id: string, patch: { display_name?: string; role?: UserRole }): Promise<ManagedUser> {
    const user = await firstValueFrom(this.http.patch<ManagedUser>(`${API_ROOT}/users/${id}`, patch));
    this.replace(user);
    return user;
  }

  async deactivate(id: string): Promise<ManagedUser> {
    const user = await firstValueFrom(this.http.post<ManagedUser>(`${API_ROOT}/users/${id}/deactivate`, {}));
    this.replace(user);
    return user;
  }

  async activate(id: string): Promise<ManagedUser> {
    const user = await firstValueFrom(this.http.post<ManagedUser>(`${API_ROOT}/users/${id}/activate`, {}));
    this.replace(user);
    return user;
  }

  /**
   * Redeem an invitation token for a password, activating the account it was
   * issued for. Unauthenticated: the token is the credential, and there is no
   * signed-in user yet to attach this call to.
   */
  async acceptInvitation(token: string, password: string): Promise<void> {
    await firstValueFrom(
      this.http.post<void>(`${API_ROOT}/users/accept-invitation`, { token, password }),
    );
  }

  /** Forget the cached page, so the next visit refetches. */
  reset(): void {
    this.itemsState.set([]);
    this.totalState.set(0);
    this.loadedState.set(false);
  }

  private replace(user: ManagedUser): void {
    this.itemsState.update((list) => list.map((item) => (item.id === user.id ? user : item)));
  }
}
