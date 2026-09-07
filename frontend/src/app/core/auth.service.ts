import { HttpClient, HttpParams } from '@angular/common/http';
import { computed, inject, Injectable, signal } from '@angular/core';
import { tap } from 'rxjs';

export interface User {
  id: string;
  email: string;
  display_name: string;
  role: 'viewer' | 'operator' | 'administrator';
  is_active: boolean;
}

interface AccessTokenResponse {
  access_token: string;
  token_type: 'bearer';
  expires_in: number;
}

export interface BootstrapAdministrator {
  email: string;
  display_name: string;
  password: string;
  bootstrap_token: string;
}

const TOKEN_KEY = 'mist-config-guardian.access-token';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly http = inject(HttpClient);
  private readonly accessToken = signal<string | null>(sessionStorage.getItem(TOKEN_KEY));

  readonly isAuthenticated = computed(() => this.accessToken() !== null);

  token(): string | null {
    return this.accessToken();
  }

  login(email: string, password: string) {
    const body = new HttpParams().set('username', email).set('password', password);
    return this.http
      .post<AccessTokenResponse>('/api/v1/auth/login', body, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      })
      .pipe(tap((response) => this.setToken(response.access_token)));
  }

  bootstrap(request: BootstrapAdministrator) {
    return this.http.post<User>('/api/v1/auth/bootstrap', request);
  }

  me() {
    return this.http.get<User>('/api/v1/auth/me');
  }

  logout(): void {
    this.accessToken.set(null);
    sessionStorage.removeItem(TOKEN_KEY);
  }

  private setToken(token: string): void {
    this.accessToken.set(token);
    sessionStorage.setItem(TOKEN_KEY, token);
  }
}
