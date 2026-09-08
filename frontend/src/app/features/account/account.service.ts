import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { computed, inject, Injectable, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';

import { API_ROOT } from '../../core/api';
import { AuthService } from '../../core/auth.service';
import { ClockPreference } from '../../core/format';
import {
  AccountProfile,
  AccountSession,
  AccountSessionList,
  EmailChangePending,
  Passkey,
  PasskeyList,
  PasskeyRegistrationOptions,
  PasswordChangeResult,
  ProfilePatch,
  RecoveryCodesResponse,
  RegisteredCredentialJson,
  SessionRevocation,
  TotpEnrollment,
} from './account.model';

const ACCOUNT = `${API_ROOT}/account`;

/**
 * The local account: profile, credentials, second factors and sessions.
 *
 * Lists are held here because the page's tab strip shows their counts before
 * the panel that owns them is mounted. Secrets — passwords, the TOTP seed and
 * recovery codes — are deliberately *not* held: they are returned from the call
 * that produced them and live only in the panel that displays them, so nothing
 * survives a navigation.
 */
@Injectable({ providedIn: 'root' })
export class AccountService {
  private readonly http = inject(HttpClient);
  private readonly auth = inject(AuthService);

  private readonly mfaOverride = signal<boolean | null>(null);
  private readonly passkeysLoaded = signal(false);
  /** Which session these panels belong to; a read outliving it is discarded. */
  private generation = 0;

  readonly sessions = signal<AccountSession[]>([]);
  readonly passkeys = signal<Passkey[]>([]);
  readonly profile = signal<AccountProfile | null>(null);

  /** Second-factor state: the signed-in user's, until this page changes it. */
  readonly mfaEnabled = computed(
    () => this.mfaOverride() ?? this.auth.user()?.mfa_enabled ?? false,
  );

  /** Registered passkeys: the list once loaded, the session's count before that. */
  readonly passkeyCount = computed(() =>
    this.passkeysLoaded() ? this.passkeys().length : (this.auth.user()?.passkey_count ?? 0),
  );

  readonly sessionCount = computed(() => this.sessions().length);

  /** The signed-in user's clock, for every timestamp this page renders. */
  readonly clock = computed<ClockPreference>(() => {
    const preferences = this.auth.user()?.preferences;
    return { timezone: preferences?.timezone ?? 'UTC', clock: preferences?.clock ?? '24h' };
  });

  // ---------------------------------------------------------------- profile

  /**
   * Await a request and let it write only while its session is still current.
   *
   * Reads and writes alike: a profile update issued by one user can answer
   * after another has signed in, and `apply` merges it into the signed-in
   * user — name, email and preferences and all.
   */
  private async owned<T>(request: Promise<T>, write: (value: T) => void): Promise<T> {
    const generation = this.generation;
    const value = await request;
    if (generation === this.generation) {
      write(value);
    }
    return value;
  }

  async loadProfile(): Promise<AccountProfile> {
    return this.owned(firstValueFrom(this.http.get<AccountProfile>(`${ACCOUNT}/profile`)), (profile) =>
      this.apply(profile),
    );
  }

  async updateProfile(patch: ProfilePatch): Promise<AccountProfile> {
    return this.owned(
      firstValueFrom(this.http.patch<AccountProfile>(`${ACCOUNT}/profile`, patch)),
      (profile) => this.apply(profile),
    );
  }

  requestEmailChange(newEmail: string, password: string): Promise<EmailChangePending> {
    return firstValueFrom(
      this.http.post<EmailChangePending>(`${ACCOUNT}/email-change`, {
        new_email: newEmail,
        password,
      }),
    );
  }

  async confirmEmailChange(token: string): Promise<AccountProfile> {
    return this.owned(
      firstValueFrom(this.http.post<AccountProfile>(`${ACCOUNT}/email-change/confirm`, { token })),
      (profile) => this.apply(profile),
    );
  }

  async cancelEmailChange(): Promise<AccountProfile> {
    return this.owned(
      firstValueFrom(this.http.delete<AccountProfile>(`${ACCOUNT}/email-change`)),
      (profile) => this.apply(profile),
    );
  }

  /**
   * Fold a profile response into the session user.
   *
   * `ProfileResponse` is narrower than `CurrentUser` — no role, no second-factor
   * state — so it is merged rather than substituted; replacing would silently
   * downgrade the role the shell reads for its permission checks.
   */
  private apply(profile: AccountProfile): AccountProfile {
    this.profile.set(profile);
    const current = this.auth.user();
    if (current) {
      this.auth.applyUser({
        ...current,
        email: profile.email,
        display_name: profile.display_name,
        preferences: profile.preferences,
      });
    }
    return profile;
  }

  // --------------------------------------------------------------- password

  /** Every other session is revoked server-side on success. */
  async changePassword(
    currentPassword: string,
    newPassword: string,
  ): Promise<PasswordChangeResult> {
    return this.owned(
      firstValueFrom(
        this.http.post<PasswordChangeResult>(`${ACCOUNT}/password`, {
          current_password: currentPassword,
          new_password: newPassword,
        }),
      ),
      // Changing a password signs the other sessions out; landing late, this
      // would prune the session list of whoever is signed in now instead.
      () => this.sessions.update((items) => items.filter((item) => item.current)),
    );
  }

  // --------------------------------------------------------------- sessions

  async loadSessions(): Promise<void> {
    await this.owned(
      firstValueFrom(this.http.get<AccountSessionList>(`${ACCOUNT}/sessions`)),
      (response) => this.sessions.set(response.items),
    );
  }

  async revokeSession(id: string): Promise<void> {
    await this.owned(
      firstValueFrom(this.http.delete<SessionRevocation>(`${ACCOUNT}/sessions/${id}`)),
      () => this.sessions.update((items) => items.filter((item) => item.id !== id)),
    );
  }

  async revokeOtherSessions(): Promise<number> {
    const generation = this.generation;
    const result = await firstValueFrom(
      this.http.post<SessionRevocation>(`${ACCOUNT}/sessions/revoke-others`, {}),
    );
    if (generation === this.generation) {
      this.sessions.update((items) => items.filter((item) => item.current));
    }
    return result.revoked_sessions;
  }

  // ------------------------------------------------------------- two-factor

  enrollTotp(): Promise<TotpEnrollment> {
    return firstValueFrom(this.http.post<TotpEnrollment>(`${ACCOUNT}/totp/enroll`, {}));
  }

  /** Confirms enrolment and returns the recovery codes, which are shown once. */
  async confirmTotp(code: string): Promise<string[]> {
    const response = await this.owned(
      firstValueFrom(this.http.post<RecoveryCodesResponse>(`${ACCOUNT}/totp/confirm`, { code })),
      () => this.mfaOverride.set(true),
    );
    return response.recovery_codes;
  }

  async disableTotp(password: string): Promise<void> {
    // `HttpClient.delete` only sends a body when one is given explicitly.
    await this.owned(
      firstValueFrom(this.http.delete<AccountProfile>(`${ACCOUNT}/totp`, { body: { password } })),
      (profile) => {
        this.apply(profile);
        this.mfaOverride.set(false);
      },
    );
  }

  async regenerateRecoveryCodes(password: string): Promise<string[]> {
    const response = await firstValueFrom(
      this.http.post<RecoveryCodesResponse>(`${ACCOUNT}/totp/recovery-codes`, { password }),
    );
    return response.recovery_codes;
  }

  // --------------------------------------------------------------- passkeys

  async loadPasskeys(): Promise<void> {
    await this.owned(firstValueFrom(this.http.get<PasskeyList>(`${ACCOUNT}/passkeys`)), (response) => {
      this.passkeys.set(response.items);
      this.passkeysLoaded.set(true);
    });
  }

  /** Adding a passkey re-checks the password: the credential outlives this session. */
  registrationOptions(password: string): Promise<PasskeyRegistrationOptions> {
    return firstValueFrom(
      this.http.post<PasskeyRegistrationOptions>(`${ACCOUNT}/passkeys/options`, { password }),
    );
  }

  async registerPasskey(
    challengeToken: string,
    credential: RegisteredCredentialJson,
    name: string,
  ): Promise<Passkey> {
    const generation = this.generation;
    const created = await firstValueFrom(
      this.http.post<Passkey>(`${ACCOUNT}/passkeys`, {
        challenge_token: challengeToken,
        credential,
        name: name || null,
      }),
    );
    if (generation === this.generation) {
      this.passkeys.update((items) => [created, ...items]);
      this.passkeysLoaded.set(true);
    }
    return created;
  }

  async renamePasskey(id: string, name: string): Promise<void> {
    await this.owned(
      firstValueFrom(this.http.patch<Passkey>(`${ACCOUNT}/passkeys/${id}`, { name })),
      (updated) => this.passkeys.update((items) => items.map((item) => (item.id === id ? updated : item))),
    );
  }

  async removePasskey(id: string, password: string): Promise<void> {
    // `HttpClient.delete` only sends a body when one is given explicitly.
    await this.owned(
      firstValueFrom(this.http.delete(`${ACCOUNT}/passkeys/${id}`, { body: { password } })),
      () => this.passkeys.update((items) => items.filter((item) => item.id !== id)),
    );
  }

  /**
   * Forget the signed-in user's own account state.
   *
   * The profile, the session list and the passkeys are the most personal
   * things the application holds, and they belong to whoever was signed in.
   * Reads still in flight are discarded with them.
   */
  reset(): void {
    this.generation += 1;
    this.profile.set(null);
    this.sessions.set([]);
    this.passkeys.set([]);
    this.passkeysLoaded.set(false);
    this.mfaOverride.set(null);
  }
}

// ---------------------------------------------------------------- messages

/**
 * The message a panel shows next to the control that failed.
 *
 * These failures are expected and local — a wrong password, a code that did not
 * verify — so they belong beside the field rather than in the shell's error
 * banner, which is reserved for a page that could not load at all.
 */
export function detailOf(cause: unknown): string {
  if (cause instanceof HttpErrorResponse) {
    const detail: unknown = (cause.error as { detail?: unknown } | null)?.detail;
    if (typeof detail === 'string' && detail.trim()) {
      return detail;
    }
    if (cause.status === 0) {
      return 'The application server is unreachable.';
    }
  }
  return 'The request could not be completed.';
}

// -------------------------------------------------------------- WebAuthn IO

/** True when this browser can run a WebAuthn registration ceremony. */
export function webauthnAvailable(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof window.PublicKeyCredential !== 'undefined' &&
    typeof navigator !== 'undefined' &&
    typeof navigator.credentials?.create === 'function'
  );
}

/**
 * Decode base64url into bytes.
 *
 * The buffer is allocated as a plain `ArrayBuffer` rather than left to the
 * `Uint8Array(length)` overload, whose `ArrayBufferLike` buffer type is not a
 * `BufferSource`: a `SharedArrayBuffer` cannot be handed to `credentials
 * .create()`. Naming the concrete buffer type keeps that guarantee in the type
 * system instead of asserting it away.
 */
export function base64UrlToBytes(value: string): Uint8Array<ArrayBuffer> {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded.padEnd(padded.length + ((4 - (padded.length % 4)) % 4), '='));
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

export function bytesToBase64Url(buffer: ArrayBuffer): string {
  let binary = '';
  for (const byte of new Uint8Array(buffer)) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Turn the JSON transport form into the binary form `create()` requires. */
export function toCreationOptions(
  json: PasskeyRegistrationOptions['options'],
): PublicKeyCredentialCreationOptions {
  return {
    challenge: base64UrlToBytes(json.challenge),
    rp: json.rp,
    user: {
      id: base64UrlToBytes(json.user.id),
      name: json.user.name,
      displayName: json.user.displayName,
    },
    pubKeyCredParams: json.pubKeyCredParams.map((parameter) => ({
      type: parameter.type as PublicKeyCredentialType,
      alg: parameter.alg,
    })),
    timeout: json.timeout,
    attestation: json.attestation as AttestationConveyancePreference | undefined,
    excludeCredentials: json.excludeCredentials?.map((descriptor) => ({
      id: base64UrlToBytes(descriptor.id),
      type: descriptor.type as PublicKeyCredentialType,
      transports: descriptor.transports as AuthenticatorTransport[] | undefined,
    })),
    authenticatorSelection: json.authenticatorSelection as
      | AuthenticatorSelectionCriteria
      | undefined,
  };
}

/** Serialize the credential the authenticator produced for the API. */
export function toRegisteredCredential(credential: PublicKeyCredential): RegisteredCredentialJson {
  const response = credential.response as AuthenticatorAttestationResponse;
  return {
    id: credential.id,
    rawId: bytesToBase64Url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults() as Record<string, unknown>,
    response: {
      clientDataJSON: bytesToBase64Url(response.clientDataJSON),
      attestationObject: bytesToBase64Url(response.attestationObject),
      transports:
        typeof response.getTransports === 'function' ? response.getTransports() : undefined,
    },
  };
}
