/**
 * The binary/JSON boundary the WebAuthn browser API sits behind.
 *
 * The API speaks `ArrayBuffer`s while the server speaks base64url, so every
 * ceremony — registering a passkey on the account page, signing in with one on
 * the login page — crosses this boundary twice. Both directions live here
 * rather than beside either feature, because a credential registered by one
 * has to decode identically for the other.
 */

/**
 * True when this browser can run the named ceremony.
 *
 * `PublicKeyCredential` is undefined outside a secure context, so this is also
 * what answers for an application served over plain HTTP: the feature is not
 * merely unused there, it is unavailable, and the caller has to say so rather
 * than offer a control that cannot work.
 */
export function webauthnSupported(operation: 'create' | 'get'): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof window.PublicKeyCredential !== 'undefined' &&
    typeof navigator !== 'undefined' &&
    typeof navigator.credentials?.[operation] === 'function'
  );
}

/**
 * Decode base64url into bytes.
 *
 * The buffer is allocated as a plain `ArrayBuffer` rather than left to the
 * `Uint8Array(length)` overload, whose `ArrayBufferLike` buffer type is not a
 * `BufferSource`: a `SharedArrayBuffer` cannot be handed to the credentials
 * API. Naming the concrete buffer type keeps that guarantee in the type system
 * instead of asserting it away.
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

/** The transport form of the options a sign-in ceremony is started with. */
export interface PasskeyRequestOptionsJson {
  challenge: string;
  timeout?: number;
  rpId?: string;
  userVerification?: string;
  allowCredentials?: { id: string; type: string; transports?: string[] }[];
}

/** The assertion an authenticator produced, in the form the API verifies. */
export interface AssertedCredentialJson {
  id: string;
  rawId: string;
  type: string;
  authenticatorAttachment: string | null;
  clientExtensionResults: Record<string, unknown>;
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle?: string;
  };
}

/** Turn the JSON transport form into the binary form `get()` requires. */
export function toRequestOptions(
  json: PasskeyRequestOptionsJson,
): PublicKeyCredentialRequestOptions {
  return {
    challenge: base64UrlToBytes(json.challenge),
    timeout: json.timeout,
    rpId: json.rpId,
    userVerification: json.userVerification as UserVerificationRequirement | undefined,
    // Absent for a passwordless sign-in: the server names no account, so the
    // authenticator offers whichever discoverable credential it holds for this
    // relying party, and the assertion is what identifies the person.
    allowCredentials: json.allowCredentials?.map((descriptor) => ({
      id: base64UrlToBytes(descriptor.id),
      type: descriptor.type as PublicKeyCredentialType,
      transports: descriptor.transports as AuthenticatorTransport[] | undefined,
    })),
  };
}

/** Serialize the assertion the authenticator produced for the API. */
export function toAssertedCredential(credential: PublicKeyCredential): AssertedCredentialJson {
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: bytesToBase64Url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults() as Record<string, unknown>,
    response: {
      clientDataJSON: bytesToBase64Url(response.clientDataJSON),
      authenticatorData: bytesToBase64Url(response.authenticatorData),
      signature: bytesToBase64Url(response.signature),
      // Omitted rather than sent as null when the authenticator returns none:
      // the field is optional in the credential JSON the server parses.
      ...(response.userHandle ? { userHandle: bytesToBase64Url(response.userHandle) } : {}),
    },
  };
}

/**
 * The ceremony was dismissed rather than failing.
 *
 * Closing the system prompt is a decision, not an error, so a caller reports it
 * as a plain note and keeps the page where it is.
 */
export function ceremonyDismissed(cause: unknown): boolean {
  return (
    cause instanceof DOMException && (cause.name === 'NotAllowedError' || cause.name === 'AbortError')
  );
}
