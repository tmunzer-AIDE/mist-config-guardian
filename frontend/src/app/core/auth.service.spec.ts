import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';

import { AuthService, CurrentUser } from './auth.service';

const USER: CurrentUser = {
  id: 'user-1',
  email: 's.kaur@northwind.example',
  display_name: 'Simran Kaur',
  role: 'administrator',
  is_active: true,
  status: 'active',
  preferences: { timezone: 'Europe/Paris', clock: '24h', landing_page: 'overview' },
  mfa_enabled: true,
  passkey_count: 0,
};

describe('AuthService', () => {
  let auth: AuthService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    auth = TestBed.inject(AuthService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  it('signs in a user who holds no second factor', async () => {
    const pending = auth.login(USER.email, 'correct horse');
    httpMock.expectOne('/api/v1/auth/login').flush({ mfa_required: false, user: USER });

    await pending;

    expect(auth.user()).toEqual(USER);
    expect(auth.role()).toBe('administrator');
  });

  it('leaves the session unauthenticated while a second factor is outstanding', async () => {
    const pending = auth.login(USER.email, 'correct horse');
    httpMock
      .expectOne('/api/v1/auth/login')
      .flush({ mfa_required: true, challenge_token: 'challenge-1', methods: ['totp'] });

    await pending;

    expect(auth.isAuthenticated()).toBe(false);
  });

  it('unwraps the user from the envelope the second factor answers with', async () => {
    // The endpoint returns the same envelope as `/auth/login`. Storing that
    // object whole leaves an MFA user with no role and no display name, which
    // reads as a viewer everywhere the shell asks.
    const pending = auth.completeMfa('challenge-1', '123456');
    httpMock.expectOne('/api/v1/auth/login/mfa').flush({
      mfa_required: false,
      access_token: 'token',
      token_type: 'bearer',
      expires_in: 1800,
      user: USER,
    });

    const resolved = await pending;

    expect(resolved).toEqual(USER);
    expect(auth.user()).toEqual(USER);
    expect(auth.role()).toBe('administrator');
    expect(auth.can('administrator')).toBe(true);
    expect(auth.initials()).toBe('SK');
  });
});
