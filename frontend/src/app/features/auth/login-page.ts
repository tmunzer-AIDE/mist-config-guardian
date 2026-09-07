import { HttpErrorResponse } from '@angular/common/http';
import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';

import { AuthService } from '../../core/auth.service';
import { SystemHealthService } from '../../core/system-health.service';

type Mode = 'login' | 'bootstrap' | 'mfa';

/**
 * Sign-in, first-administrator bootstrap, and the second-factor challenge.
 *
 * The approved design does not define this screen, so it is built from the same
 * tokens and control primitives as the rest of the application rather than
 * inventing a second visual language.
 */
@Component({
  selector: 'app-login-page',
  imports: [ReactiveFormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './login-page.html',
  styleUrl: './login-page.scss',
})
export class LoginPage {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  protected readonly health = inject(SystemHealthService);

  protected readonly mode = signal<Mode>('login');
  protected readonly busy = signal(false);
  protected readonly error = signal('');
  protected readonly notice = signal('');
  protected readonly passkeySupported = signal(typeof PublicKeyCredential !== 'undefined');

  private readonly challengeToken = signal('');

  protected readonly heading = computed(() => {
    switch (this.mode()) {
      case 'bootstrap':
        return 'Create the first administrator';
      case 'mfa':
        return 'Confirm your second factor';
      default:
        return 'Sign in';
    }
  });

  protected readonly loginForm = new FormGroup({
    email: new FormControl('', { nonNullable: true, validators: [Validators.required, Validators.email] }),
    password: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
  });

  protected readonly mfaForm = new FormGroup({
    code: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
  });

  protected readonly bootstrapForm = new FormGroup({
    display_name: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
    email: new FormControl('', { nonNullable: true, validators: [Validators.required, Validators.email] }),
    password: new FormControl('', {
      nonNullable: true,
      validators: [Validators.required, Validators.minLength(12)],
    }),
    bootstrap_token: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
  });

  constructor() {
    void this.health.loadVersion();
  }

  protected switchMode(mode: Mode): void {
    this.mode.set(mode);
    this.error.set('');
  }

  protected async login(): Promise<void> {
    if (this.loginForm.invalid || this.busy()) {
      this.loginForm.markAllAsTouched();
      return;
    }
    const { email, password } = this.loginForm.getRawValue();
    await this.attempt(async () => {
      const result = await this.auth.login(email, password);
      if (result.mfa_required) {
        this.challengeToken.set(result.challenge_token);
        this.mode.set('mfa');
        this.notice.set('');
        return;
      }
      this.loginForm.controls.password.reset();
      await this.land();
    });
  }

  protected async verifyMfa(): Promise<void> {
    const code = this.mfaForm.controls.code.value.trim();
    if (!code || this.busy()) {
      return;
    }
    await this.attempt(async () => {
      await this.auth.completeMfa(this.challengeToken(), code);
      this.mfaForm.reset();
      this.challengeToken.set('');
      await this.land();
    });
  }

  protected async bootstrap(): Promise<void> {
    if (this.bootstrapForm.invalid || this.busy()) {
      this.bootstrapForm.markAllAsTouched();
      return;
    }
    const request = this.bootstrapForm.getRawValue();
    await this.attempt(async () => {
      await this.auth.bootstrapAdministrator(request);
      this.loginForm.controls.email.setValue(request.email);
      this.bootstrapForm.reset();
      this.notice.set('Administrator created. Sign in to continue.');
      this.mode.set('login');
    });
  }

  private async attempt(work: () => Promise<void>): Promise<void> {
    this.busy.set(true);
    this.error.set('');
    try {
      await work();
    } catch (cause) {
      this.error.set(describe(cause));
    } finally {
      this.busy.set(false);
    }
  }

  /** Return to the page the guard interrupted, or the account's landing page. */
  private async land(): Promise<void> {
    const next = this.route.snapshot.queryParamMap.get('next');
    if (next && next.startsWith('/') && !next.startsWith('//')) {
      await this.router.navigateByUrl(next);
      return;
    }
    const landing = this.auth.user()?.preferences.landing_page ?? 'overview';
    await this.router.navigate([landing === 'overview' ? '/' : `/${landing}`]);
  }
}

function describe(cause: unknown): string {
  if (cause instanceof HttpErrorResponse) {
    const detail: unknown = (cause.error as { detail?: unknown } | null)?.detail;
    if (typeof detail === 'string') {
      return detail;
    }
    if (cause.status === 0) {
      return 'The application server is unreachable.';
    }
  }
  return 'The request could not be completed.';
}
