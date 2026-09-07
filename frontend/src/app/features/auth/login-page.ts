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

  protected readonly mode = signal<'login' | 'bootstrap'>('login');
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

  protected switchMode(mode: 'login' | 'bootstrap'): void {
    this.mode.set(mode);
    this.error.set('');
  }

  protected login(): void {
    if (this.loginForm.invalid || this.busy()) {
      this.loginForm.markAllAsTouched();
      return;
    }
    this.busy.set(true);
    this.error.set('');
    const { email, password } = this.loginForm.getRawValue();
    this.auth
      .login(email, password)
      .pipe(finalize(() => this.busy.set(false)))
      .subscribe({
        next: () => void this.router.navigate(['/organizations']),
        error: (error: HttpErrorResponse) => this.error.set(this.errorMessage(error)),
      });
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
    return typeof error.error?.detail === 'string' ? error.error.detail : 'The request could not be completed.';
  }
}
