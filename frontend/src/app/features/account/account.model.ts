/**
 * Payloads for the `/account` endpoints.
 *
 * The account API is the only place the application writes to the local user
 * record; Mist credentials live entirely on the organization side and are never
 * part of these shapes. Every interface below mirrors a schema in
 * `backend/src/mist_config_guardian_backend/schemas/account.py`.
 */

import { ClockFormat, LandingPage, UserPreferences } from '../../core/auth.service';

/** The five panels of the account page, and the `?tab=` values that select them. */
export type AccountTab = 'profile' | 'password' | 'two-factor' | 'passkeys' | 'sessions';

export const ACCOUNT_TABS: readonly AccountTab[] = [
  'profile',
  'password',
  'two-factor',
  'passkeys',
  'sessions',
] as const;

/** Resolve a `?tab=` value, falling back to the first panel. */
export function normalizeTab(value: string | null | undefined): AccountTab {
  const candidate = (value ?? '').trim().toLowerCase();
  return (ACCOUNT_TABS as readonly string[]).includes(candidate)
    ? (candidate as AccountTab)
    : 'profile';
}

// ------------------------------------------------------------------ profile

/**
 * `GET|PATCH /account/profile` — the editable half of the user record.
 *
 * Narrower than `CurrentUser`: it carries no role and no second-factor state,
 * so applying it to the session means merging, never replacing.
 */
export interface AccountProfile {
  id: string;
  email: string;
  display_name: string;
  preferences: UserPreferences;
  pending_email: string | null;
  pending_email_expires_at: string | null;
  password_changed_at: string | null;
}

/** `PATCH /account/profile` — every field optional, only sent when changed. */
export interface ProfilePatch {
  display_name?: string;
  timezone?: string;
  clock?: ClockFormat;
  landing_page?: LandingPage;
}

/** `POST /account/email-change`. */
export interface EmailChangePending {
  pending_email: string;
  expires_at: string;
  /**
   * Populated only outside production. The deployment has no mail transport,
   * so the token comes back here for the operator to confirm inline; the UI
   * must never claim a message was delivered.
   */
  confirmation_token: string | null;
  delivery: 'not_implemented';
}

// ----------------------------------------------------------------- password

/** `POST /account/password`. */
export interface PasswordChangeResult {
  password_changed_at: string;
  revoked_sessions: number;
}

// ----------------------------------------------------------------- sessions

export interface AccountSession {
  id: string;
  label: string;
  ip_address: string | null;
  location: string | null;
  created_at: string;
  last_seen_at: string;
  expires_at: string;
  mfa_verified_at: string | null;
  current: boolean;
}

export interface AccountSessionList {
  items: AccountSession[];
  total: number;
}

export interface SessionRevocation {
  revoked_sessions: number;
}

// --------------------------------------------------------------- two-factor

/** `POST /account/totp/enroll` — returned exactly once per enrolment. */
export interface TotpEnrollment {
  secret: string;
  otpauth_uri: string;
  issuer: string;
  /** Inline SVG for the provisioning code, rendered server-side. */
  qr_svg: string;
}

/** `POST /account/totp/confirm` and `POST /account/totp/recovery-codes`. */
export interface RecoveryCodesResponse {
  recovery_codes: string[];
  generated_at: string;
}

// ----------------------------------------------------------------- passkeys

export type PasskeyDeviceKind = 'platform' | 'security_key';

export interface Passkey {
  id: string;
  name: string;
  device_kind: PasskeyDeviceKind;
  transports: string[];
  backed_up: boolean;
  created_at: string;
  last_used_at: string | null;
}

export interface PasskeyList {
  items: Passkey[];
  total: number;
}

/**
 * WebAuthn creation options in the base64url JSON transport form produced by
 * `webauthn.helpers.options_to_json_dict`.
 */
export interface PasskeyCreationOptionsJson {
  challenge: string;
  rp: { id?: string; name: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: { type: string; alg: number }[];
  timeout?: number;
  attestation?: string;
  excludeCredentials?: { id: string; type: string; transports?: string[] }[];
  authenticatorSelection?: {
    authenticatorAttachment?: string;
    residentKey?: string;
    requireResidentKey?: boolean;
    userVerification?: string;
  };
}

/**
 * `POST /account/passkeys/options`.
 *
 * The challenge itself never leaves the server: `challenge_token` only names
 * the stored one, and has to be handed back with the attestation.
 */
export interface PasskeyRegistrationOptions {
  challenge_token: string;
  options: PasskeyCreationOptionsJson;
}

/** The registration result, in the shape `PublicKeyCredential.toJSON()` produces. */
export interface RegisteredCredentialJson {
  id: string;
  rawId: string;
  type: string;
  authenticatorAttachment?: string | null;
  clientExtensionResults: Record<string, unknown>;
  response: {
    clientDataJSON: string;
    attestationObject: string;
    transports?: string[];
  };
}
