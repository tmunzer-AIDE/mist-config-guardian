import { HttpErrorResponse } from '@angular/common/http';
import { ChangeDetectionStrategy, Component, computed, inject, output, signal } from '@angular/core';
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';

import { AuthService, UserRole } from '../../core/auth.service';
import { formatInstant } from '../../core/format';
import { Tone } from '../../core/tone';
import { ManagedUser, UserInviteResult, UsersService } from './users.service';
import { type ConfirmRequest } from './settings-page';

const ROLES: readonly UserRole[] = ['viewer', 'operator', 'administrator'];

/**
 * The users and roles panel.
 *
 * The API refuses to demote or deactivate the signed-in administrator, and
 * refuses to remove the last active administrator. Those two rules are mirrored
 * here as disabled controls with an explanation, so an administrator learns why
 * before clicking rather than from a 409 afterwards.
 */
@Component({
  selector: 'app-users-tab',
  imports: [ReactiveFormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './users-tab.html',
  styleUrl: './users-tab.scss',
})
export class UsersTab {
  private readonly users = inject(UsersService);
  private readonly auth = inject(AuthService);

  readonly confirmRequested = output<ConfirmRequest>();

  protected readonly roles = ROLES;

  protected readonly canManage = computed(() => {
    this.auth.user();
    return this.auth.can('administrator');
  });

  protected readonly inviteOpen = signal(false);
  protected readonly busyId = signal('');
  protected readonly notice = signal('');
  protected readonly error = signal('');
  /** The link to hand over, and the email it was issued for. */
  protected readonly invitationLink = signal<{ email: string; url: string } | null>(null);
  protected readonly linkCopied = signal(false);
  protected readonly canCopyLink = computed(() => typeof navigator?.clipboard?.writeText === 'function');

  protected readonly inviteForm = new FormGroup({
    email: new FormControl('', { nonNullable: true, validators: [Validators.required, Validators.email] }),
    display_name: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
    role: new FormControl<UserRole>('viewer', { nonNullable: true }),
  });

  /** Active administrators, the count that gates every demote and deactivate. */
  protected readonly activeAdministrators = computed(
    () => this.users.items().filter(isActiveAdministrator).length,
  );

  protected readonly rows = computed(() => {
    const selfId = this.auth.user()?.id ?? '';
    const lastAdministrator = this.activeAdministrators() <= 1;
    return this.users.items().map((user) => {
      const isSelf = user.id === selfId;
      const guard = demotionGuard(user, isSelf, lastAdministrator);
      return {
        user,
        id: user.id,
        name: user.display_name,
        email: user.email,
        role: user.role,
        roleLabel: user.role.toUpperCase(),
        roleTone: roleTone(user),
        status: user.status.toUpperCase(),
        statusTone: statusTone(user),
        mfa: user.mfa_enabled ? 'ENABLED' : 'OFF',
        mfaTone: mfaTone(user),
        lastSignIn: user.last_login_at ? formatInstant(new Date(user.last_login_at)) : 'never',
        isSelf,
        guard,
        canDeactivate: user.is_active && guard === '',
        canActivate: !user.is_active,
        canResend: user.status === 'invited',
      };
    });
  });

  protected isBusy(id: string): boolean {
    return this.busyId() === id;
  }

  protected openInvite(): void {
    this.inviteOpen.set(true);
    this.error.set('');
    this.notice.set('');
    this.invitationLink.set(null);
    this.linkCopied.set(false);
    this.inviteForm.reset({ email: '', display_name: '', role: 'viewer' });
  }

  protected closeInvite(): void {
    this.inviteOpen.set(false);
    this.inviteForm.reset({ email: '', display_name: '', role: 'viewer' });
  }

  protected async invite(): Promise<void> {
    if (this.inviteForm.invalid || this.busyId()) {
      this.inviteForm.markAllAsTouched();
      return;
    }
    const value = this.inviteForm.getRawValue();
    await this.run('invite', async () => {
      const result = await this.users.invite({
        email: value.email.trim(),
        display_name: value.display_name.trim(),
        role: value.role,
      });
      this.closeInvite();
      this.applyInviteResult(result);
    });
  }

  protected async resend(user: ManagedUser): Promise<void> {
    await this.run(user.id, async () => {
      const result = await this.users.resendInvitation(user.id);
      this.applyInviteResult(result);
    });
  }

  /** The link to hand over, preferring the canonical one the backend built. */
  private activationLink(result: UserInviteResult): string | null {
    if (result.invitation_url) {
      return result.invitation_url;
    }
    if (!result.invitation_token) {
      return null;
    }
    // The backend could not resolve a canonical origin. This is display only,
    // for an administrator already on this origin: the server neither reads
    // nor sends it, and it is unreachable whenever an email was attempted.
    return `${document.baseURI.replace(/\/$/, '')}/accept-invitation#token=${encodeURIComponent(
      result.invitation_token,
    )}`;
  }

  private deliveryNotice(result: UserInviteResult): string {
    const email = result.user.email;
    switch (result.delivery) {
      case 'sent':
        return `Invitation emailed to ${email}.`;
      case 'uncertain':
        return `Sent to ${email}, but the mail server did not confirm. Share this link if it does not arrive.`;
      case 'not_configured':
        return `No SMTP server is configured, so no email was sent. Share this link with ${email}.`;
      case 'failed':
        return `Email to ${email} failed: ${result.delivery_detail ?? 'unknown error'}. Share this link instead.`;
    }
  }

  private applyInviteResult(result: UserInviteResult): void {
    const url = this.activationLink(result);
    this.invitationLink.set(url ? { email: result.user.email, url } : null);
    this.linkCopied.set(false);
    this.notice.set(this.deliveryNotice(result));
  }

  protected async copyLink(url: string): Promise<void> {
    if (!this.canCopyLink()) {
      return;
    }
    try {
      await navigator.clipboard.writeText(url);
      this.linkCopied.set(true);
    } catch {
      this.error.set('The browser refused access to the clipboard. Select the link and copy it.');
    }
  }

  protected async changeRole(user: ManagedUser, event: Event): Promise<void> {
    const role = (event.target as HTMLSelectElement).value as UserRole;
    if (role === user.role) {
      return;
    }
    await this.run(user.id, async () => {
      const updated = await this.users.update(user.id, { role });
      this.notice.set(`${updated.display_name} is now ${updated.role}.`);
    });
  }

  protected requestDeactivate(user: ManagedUser): void {
    this.confirmRequested.emit({
      title: `Deactivate ${user.display_name}?`,
      body: `${user.email} is signed out of every session immediately and cannot sign in again until the account is reactivated. Nothing they created is deleted.`,
      confirmLabel: 'Deactivate account',
      danger: true,
      run: async () => {
        await this.run(user.id, async () => {
          await this.users.deactivate(user.id);
          this.notice.set(`${user.display_name} was deactivated.`);
        });
      },
    });
  }

  protected async activate(user: ManagedUser): Promise<void> {
    await this.run(user.id, async () => {
      await this.users.activate(user.id);
      this.notice.set(`${user.display_name} was reactivated.`);
    });
  }

  private async run(id: string, work: () => Promise<void>): Promise<void> {
    if (this.busyId()) {
      return;
    }
    this.busyId.set(id);
    this.error.set('');
    this.notice.set('');
    try {
      await work();
    } catch (cause) {
      this.error.set(detailOf(cause));
    } finally {
      this.busyId.set('');
    }
  }
}

function isActiveAdministrator(user: ManagedUser): boolean {
  return user.role === 'administrator' && user.is_active;
}

/**
 * Why this account's role and activation are locked, or the empty string.
 *
 * Both rules exist to keep at least one person able to administer the
 * deployment: an administrator who demotes themselves, or the only remaining
 * administrator, would leave nobody able to undo it.
 */
export function demotionGuard(user: ManagedUser, isSelf: boolean, lastAdministrator: boolean): string {
  if (user.role !== 'administrator') {
    return '';
  }
  if (isSelf) {
    return 'You cannot change your own administrator role or deactivate your own account. Ask another administrator.';
  }
  if (lastAdministrator && user.is_active) {
    return 'This is the last active administrator. Promote another account first.';
  }
  return '';
}

function roleTone(user: ManagedUser): Tone {
  return user.role === 'administrator' ? 'info' : 'none';
}

function mfaTone(user: ManagedUser): Tone {
  return user.mfa_enabled ? 'ok' : 'none';
}

function statusTone(user: ManagedUser): Tone {
  if (!user.is_active) {
    return 'none';
  }
  return user.status === 'active' ? 'ok' : 'warn';
}

function detailOf(cause: unknown): string {
  if (cause instanceof HttpErrorResponse) {
    const detail: unknown = (cause.error as { detail?: unknown } | null)?.detail;
    if (typeof detail === 'string') {
      return detail;
    }
    if (cause.status === 409) {
      return 'The deployment must keep at least one active administrator.';
    }
  }
  return 'The request could not be completed.';
}
