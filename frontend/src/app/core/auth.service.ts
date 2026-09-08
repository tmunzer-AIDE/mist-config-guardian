import { HttpClient, HttpParams } from '@angular/common/http';
import { computed, inject, Injectable, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';

import { API_ROOT } from './api';

export type UserRole = 'viewer' | 'operator' | 'administrator';
export type ClockFormat = '24h' | '12h';
export type LandingPage = 'overview' | 'changes' | 'history' | 'restore' | 'impact';

export interface UserPreferences {
  timezone: string;
  clock: ClockFormat;
  landing_page: LandingPage;
}

export interface CurrentUser {
  id: string;
  email: string;
  display_name: string;
  role: UserRole;
  is_active: boolean;
  status: 'invited' | 'active' | 'deactivated';
  preferences: UserPreferences;
  mfa_enabled: boolean;
  passkey_count: number;
}

export interface LoginChallenge {
  mfa_required: true;
  challenge_token: string;
  methods: string[];
}

export interface LoginSuccess {
  mfa_required: false;
  user: CurrentUser;
}

export type LoginResult = LoginSuccess | LoginChallenge;

export interface BootstrapAdministrator {
  email: string;
  display_name: string;
  password: string;
  bootstrap_token: string;
}

const ROLE_RANK: Record<UserRole, number> = { viewer: 0, operator: 1, administrator: 2 };

/**
 * Authentication against cookie-backed sessions.
 *
 * The session and CSRF cookies are set by the API; the browser never holds a
 * bearer token, so an injected script cannot exfiltrate one.
 */
@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly http = inject(HttpClient);
  private readonly userState = signal<CurrentUser | null>(null);
  private readonly resolvedState = signal(false);

  readonly user = this.userState.asReadonly();
  readonly resolved = this.resolvedState.asReadonly();
  readonly isAuthenticated = computed(() => this.userState() !== null);
  readonly role = computed<UserRole>(() => this.userState()?.role ?? 'viewer');

  /** True when the signed-in user holds at least the given role. */
  can(minimum: UserRole): boolean {
    const current = this.userState();
    return current !== null && ROLE_RANK[current.role] >= ROLE_RANK[minimum];
  }

  /** Resolve the current session once at start-up. Never throws. */
  async restore(): Promise<void> {
    if (this.resolvedState()) {
      return;
    }
    try {
      this.userState.set(await firstValueFrom(this.http.get<CurrentUser>(`${API_ROOT}/auth/me`)));
    } catch {
      this.userState.set(null);
    } finally {
      this.resolvedState.set(true);
    }
  }

  async login(email: string, password: string): Promise<LoginResult> {
    const body = new HttpParams().set('username', email).set('password', password);
    const response = await firstValueFrom(
      this.http.post<LoginResult>(`${API_ROOT}/auth/login`, body, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      }),
    );
    if (!response.mfa_required) {
      this.userState.set(response.user);
      this.resolvedState.set(true);
    }
    return response;
  }

  async completeMfa(challengeToken: string, code: string): Promise<CurrentUser> {
    // The endpoint answers with the same envelope as `/auth/login`, so the user
    // has to be unwrapped from it: storing the envelope itself would leave the
    // signed-in user with no role and no display name.
    const response = await firstValueFrom(
      this.http.post<LoginSuccess>(`${API_ROOT}/auth/login/mfa`, {
        challenge_token: challengeToken,
        code,
      }),
    );
    this.userState.set(response.user);
    this.resolvedState.set(true);
    return response.user;
  }

  async bootstrapAdministrator(request: BootstrapAdministrator): Promise<CurrentUser> {
    return firstValueFrom(this.http.post<CurrentUser>(`${API_ROOT}/auth/bootstrap`, request));
  }

  async logout(): Promise<void> {
    try {
      await firstValueFrom(this.http.post(`${API_ROOT}/auth/logout`, {}));
    } finally {
      this.userState.set(null);
    }
  }

  /**
   * Drop the session the browser believes it holds, without calling the API.
   *
   * Used when the server has already rejected the session — revoked from
   * another device, expired, or signed out elsewhere. Calling `logout` would
   * only produce a second failing request.
   */
  forgetSession(): void {
    this.userState.set(null);
    this.resolvedState.set(true);
  }

  /** Apply a profile update returned by the account API. */
  applyUser(user: CurrentUser): void {
    this.userState.set(user);
  }

  /** Initials shown in the header avatar. */
  initials(): string {
    const name = this.userState()?.display_name.trim() ?? '';
    if (!name) {
      return '··';
    }
    const parts = name.split(/\s+/);
    const letters = parts.length > 1 ? `${parts[0][0]}${parts[parts.length - 1][0]}` : name.slice(0, 2);
    return letters.toUpperCase();
  }
}
