import { HttpErrorResponse } from '@angular/common/http';
import { inject, Injectable, signal } from '@angular/core';
import { NavigationStart, Router } from '@angular/router';

/** Credentials stay in the caller's pending request, never in persistent storage. */
@Injectable({ providedIn: 'root' })
export class MistMfaService {
  private readonly router = inject(Router);
  readonly prompt = signal<{ message: string; complete: (code: string | null) => void } | null>(null);

  async run<T>(request: (code?: string) => Promise<T>): Promise<T> {
    let cancelled = false;
    const navigation = this.router.events.subscribe(event => {
      if (event instanceof NavigationStart) {
        cancelled = true;
        this.prompt()?.complete(null);
      }
    });
    let code: string | undefined;
    try {
      while (true) {
        try {
          return await request(code);
        } catch (error) {
          if (cancelled || !(error instanceof HttpErrorResponse) || error.status !== 409 ||
              error.error?.detail?.code !== 'mist_mfa_required') {
            throw error;
          }
          code = await this.ask(code ? 'The code was not accepted. Enter a new Mist verification code.' :
            'Enter the verification code for your Mist account.');
        }
      }
    } finally {
      navigation.unsubscribe();
    }
  }

  private ask(message: string): Promise<string> {
    this.prompt()?.complete(null);
    return new Promise((resolve, reject) => {
      const complete = (code: string | null) => {
        clearTimeout(timeout);
        this.prompt.set(null);
        if (code) {
          resolve(code);
        } else {
          reject(new HttpErrorResponse({ status: 400, error: { detail: 'Mist verification cancelled or expired. Sign in again to continue.' } }));
        }
      };
      const timeout = setTimeout(() => complete(null), 180_000);
      this.prompt.set({ message, complete });
    });
  }
}
