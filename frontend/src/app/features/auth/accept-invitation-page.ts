import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import {
  AbstractControl,
  FormControl,
  FormGroup,
  ReactiveFormsModule,
  ValidationErrors,
  Validators,
} from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { take } from 'rxjs';

import { UsersService } from '../settings/users.service';

/**
 * Shown for every unusable token — missing, malformed, expired, or already
 * accepted — and for any error the accept call itself returns.
 *
 * The backend deliberately returns one indistinct error for all of those
 * cases so an attacker holding a dead link cannot learn which case they hit;
 * the UI must not narrow that back down by wording the failure differently
 * per cause.
 */
const INVITATION_FAILURE = 'This invitation is invalid or has expired.';

/** A password and its confirmation must match before the API is ever asked. */
function passwordsMatch(group: AbstractControl): ValidationErrors | null {
  const { password, confirm } = group.value as { password: string; confirm: string };
  return password === confirm ? null : { mismatch: true };
}

/**
 * The page an invitation link opens: `{base}/accept-invitation#token=...`.
 *
 * Unauthenticated by design — the invitee has no account yet, and the token
 * in the fragment is itself the credential. It is read from the fragment
 * rather than a query parameter because a query string is written to ingress
 * and proxy logs, browser history, and `Referer` headers; a fragment is
 * never sent to a server. The fragment is read once and then scrubbed from
 * the address bar immediately, so the token does not linger in history once
 * this page has it.
 *
 * The approved design does not define this screen, so it is built from the
 * same tokens and control primitives as the sign-in page rather than
 * inventing a second visual language.
 */
@Component({
  selector: 'app-accept-invitation-page',
  imports: [ReactiveFormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './accept-invitation-page.html',
  styleUrl: './accept-invitation-page.scss',
})
export class AcceptInvitationPage {
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly users = inject(UsersService);

  private readonly token = signal<string | null>(null);

  /** Public so tests can assert on it directly, without inspecting the DOM. */
  readonly hasToken = computed(() => this.token() !== null);
  protected readonly failureMessage = INVITATION_FAILURE;
  protected readonly busy = signal(false);
  protected readonly error = signal('');

  protected readonly acceptForm = new FormGroup(
    {
      password: new FormControl('', {
        nonNullable: true,
        validators: [Validators.required, Validators.minLength(12)],
      }),
      confirm: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
    },
    { validators: passwordsMatch },
  );

  constructor() {
    this.route.fragment.pipe(take(1)).subscribe((fragment) => {
      const params = new URLSearchParams(fragment ?? '');
      this.token.set(params.get('token'));
      // Immediately, so the credential does not persist in browser history
      // now that this page has read it out of the fragment.
      history.replaceState(null, '', location.pathname);
    });
  }

  protected async accept(): Promise<void> {
    const token = this.token();
    if (!token || this.acceptForm.invalid || this.busy()) {
      this.acceptForm.markAllAsTouched();
      return;
    }
    this.busy.set(true);
    this.error.set('');
    try {
      await this.users.acceptInvitation(token, this.acceptForm.getRawValue().password);
      await this.router.navigate(['/login']);
    } catch {
      // Every failure — invalid, expired, already accepted, or a transport
      // error — reads the same way. Distinguishing them here would hand back
      // exactly the signal the indistinct backend error withholds.
      this.error.set(INVITATION_FAILURE);
    } finally {
      this.busy.set(false);
    }
  }
}
