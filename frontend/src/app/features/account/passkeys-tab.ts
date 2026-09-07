import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';

import { formatDate, formatInstant } from '../../core/format';
import { Passkey } from './account.model';
import {
  AccountService,
  detailOf,
  toCreationOptions,
  toRegisteredCredential,
  webauthnAvailable,
} from './account.service';

/**
 * The ceremony was dismissed rather than failing.
 *
 * A user who closes the system prompt has not hit an error, so this is reported
 * as a plain note; only a genuine failure gets the error treatment.
 */
function wasDismissed(cause: unknown): boolean {
  return (
    cause instanceof DOMException &&
    (cause.name === 'NotAllowedError' || cause.name === 'AbortError')
  );
}

@Component({
  selector: 'app-passkeys-tab',
  imports: [],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './passkeys-tab.html',
  styleUrl: './passkeys-tab.scss',
})
export class PasskeysTab {
  private readonly account = inject(AccountService);

  /** Resolved once: whether this browser can run a registration ceremony. */
  protected readonly supported = signal(webauthnAvailable());

  protected readonly adding = signal(false);
  protected readonly error = signal('');
  protected readonly notice = signal('');
  protected readonly busyId = signal('');

  private readonly renamingId = signal('');
  private readonly draftName = signal('');

  protected readonly renaming = this.renamingId.asReadonly();
  protected readonly draft = this.draftName.asReadonly();

  protected readonly credentials = computed(() =>
    this.account.passkeys().map((passkey) => this.toRow(passkey)),
  );

  protected readonly empty = computed(() => this.account.passkeys().length === 0);

  // -------------------------------------------------------------- add flow

  protected async add(): Promise<void> {
    if (!this.supported() || this.adding()) {
      return;
    }
    this.adding.set(true);
    this.error.set('');
    this.notice.set('');
    try {
      const { challenge_token, options } = await this.account.registrationOptions();
      const created = await navigator.credentials.create({
        publicKey: toCreationOptions(options),
      });
      if (created === null) {
        this.notice.set('No passkey was added: your device did not return a credential.');
        return;
      }
      const credential = created as PublicKeyCredential;
      const registered = toRegisteredCredential(credential);
      const passkey = await this.account.registerPasskey(
        challenge_token,
        registered,
        defaultName(credential),
      );
      this.notice.set(`Added ${passkey.name}. You can rename it below.`);
    } catch (cause) {
      if (wasDismissed(cause)) {
        this.notice.set(
          'No passkey was added. The request was dismissed on your device, or the device was already registered.',
        );
      } else {
        this.error.set(detailOf(cause));
      }
    } finally {
      this.adding.set(false);
    }
  }

  // ---------------------------------------------------------------- rename

  protected startRename(passkey: { id: string; name: string }): void {
    this.renamingId.set(passkey.id);
    this.draftName.set(passkey.name);
    this.error.set('');
  }

  protected setDraft(event: Event): void {
    this.draftName.set((event.target as HTMLInputElement).value);
  }

  protected cancelRename(): void {
    this.renamingId.set('');
    this.draftName.set('');
  }

  protected async saveRename(id: string): Promise<void> {
    const name = this.draftName().trim();
    if (!name || this.busyId()) {
      return;
    }
    this.busyId.set(id);
    this.error.set('');
    try {
      await this.account.renamePasskey(id, name);
      this.cancelRename();
      this.notice.set('Passkey renamed.');
    } catch (cause) {
      this.error.set(detailOf(cause));
    } finally {
      this.busyId.set('');
    }
  }

  // ---------------------------------------------------------------- remove

  protected async remove(id: string, name: string): Promise<void> {
    if (this.busyId()) {
      return;
    }
    this.busyId.set(id);
    this.error.set('');
    try {
      await this.account.removePasskey(id);
      this.notice.set(`Removed ${name}.`);
    } catch (cause) {
      this.error.set(detailOf(cause));
    } finally {
      this.busyId.set('');
    }
  }

  private toRow(passkey: Passkey) {
    const clock = this.account.clock();
    return {
      id: passkey.id,
      name: passkey.name,
      platform: passkey.device_kind === 'platform',
      kind: passkey.device_kind === 'platform' ? 'PLATFORM' : 'SECURITY KEY',
      meta: `ADDED ${formatDate(new Date(passkey.created_at), clock)} · LAST USED ${
        passkey.last_used_at ? formatInstant(new Date(passkey.last_used_at), clock) : 'NEVER'
      }`,
    };
  }
}

/**
 * A first name for a freshly registered credential.
 *
 * The server defaults to a bare "Passkey"; naming by attachment gives the
 * operator something to recognise in the list before they rename it.
 */
function defaultName(credential: PublicKeyCredential): string {
  return credential.authenticatorAttachment === 'cross-platform'
    ? 'Security key'
    : 'This device';
}
