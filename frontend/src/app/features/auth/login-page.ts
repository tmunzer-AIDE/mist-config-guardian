import { HttpErrorResponse } from '@angular/common/http';
import { Component, inject, signal } from '@angular/core';
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { finalize } from 'rxjs';

import { AuthService } from '../../core/auth.service';

@Component({
  selector: 'app-login-page',
  imports: [ReactiveFormsModule],
  templateUrl: './login-page.html',
  styleUrl: './login-page.scss',
})
export class LoginPage {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);

  protected readonly mode = signal<'login' | 'bootstrap' | 'mfa'>('login');
  protected readonly challengeToken = signal('');
  protected readonly mfaForm = new FormGroup({
    code: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
  });
  protected readonly busy = signal(false);
  protected readonly error = signal('');
  protected readonly bootstrapCreated = signal(false);

  protected readonly loginForm = new FormGroup({
    email: new FormControl('', {
      nonNullable: true,
      validators: [Validators.required, Validators.email],
    }),
    password: new FormControl('', {
      nonNullable: true,
      validators: [Validators.required],
    }),
  });

  protected readonly bootstrapForm = new FormGroup({
    display_name: new FormControl('', {
      nonNullable: true,
      validators: [Validators.required],
    }),
    email: new FormControl('', {
      nonNullable: true,
      validators: [Validators.required, Validators.email],
    }),
    password: new FormControl('', {
      nonNullable: true,
      validators: [Validators.required, Validators.minLength(12)],
    }),
    bootstrap_token: new FormControl('', {
      nonNullable: true,
      validators: [Validators.required],
    }),
  });

  protected switchMode(mode: 'login' | 'bootstrap' | 'mfa'): void {
    this.mode.set(mode);
    this.error.set('');
  }

  protected async login(): Promise<void> {
    if (this.loginForm.invalid || this.busy()) {
      this.loginForm.markAllAsTouched();
      return;
    }
    this.busy.set(true);
    this.error.set('');
    const { email, password } = this.loginForm.getRawValue();
    try {
      const result = await this.auth.login(email, password);
      if (result.mfa_required) {
        this.challengeToken.set(result.challenge_token);
        this.mode.set('mfa');
        return;
      }
      await this.router.navigate(['/']);
    } catch (cause) {
      this.error.set(this.errorMessage(cause as HttpErrorResponse));
    } finally {
      this.busy.set(false);
    }
  }

  protected async verifyMfa(): Promise<void> {
    const code = this.mfaForm.controls.code.value.trim();
    if (!code || this.busy()) {
      return;
    }
    this.busy.set(true);
    this.error.set('');
    try {
      await this.auth.completeMfa(this.challengeToken(), code);
      await this.router.navigate(['/']);
    } catch (cause) {
      this.error.set(this.errorMessage(cause as HttpErrorResponse));
    } finally {
      this.busy.set(false);
    }
  }

  protected bootstrap(): void {
    if (this.bootstrapForm.invalid || this.busy()) {
      this.bootstrapForm.markAllAsTouched();
      return;
    }
    this.busy.set(true);
    this.error.set('');
    this.auth
      .bootstrap(this.bootstrapForm.getRawValue())
      .pipe(finalize(() => this.busy.set(false)))
      .subscribe({
        next: () => {
          this.bootstrapCreated.set(true);
          this.loginForm.controls.email.setValue(this.bootstrapForm.controls.email.value);
          this.switchMode('login');
        },
        error: (error: HttpErrorResponse) => this.error.set(this.errorMessage(error)),
      });
  }

  private errorMessage(error: HttpErrorResponse): string {
    const detail: unknown = (error.error as { detail?: unknown } | null)?.detail;
    return typeof detail === 'string' ? detail : 'The request could not be completed.';
  }
}
