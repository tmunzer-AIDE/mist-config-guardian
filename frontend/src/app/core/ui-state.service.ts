import { HttpErrorResponse } from '@angular/common/http';
import { Injectable, signal } from '@angular/core';

/** A dismissible application-level failure, rendered as the shell error banner. */
export interface AppError {
  title: string;
  detail: string;
  code: string;
}

/**
 * Global loading and error state owned by the shell.
 *
 * Pages call `begin`/`end` around their initial fetch so the shell can render
 * the shimmer skeleton instead of a half-populated page.
 */
@Injectable({ providedIn: 'root' })
export class UiStateService {
  private readonly pending = signal(0);
  private readonly labelState = signal('');
  private readonly errorState = signal<AppError | null>(null);

  readonly loading = signal(false);
  readonly label = this.labelState.asReadonly();
  readonly error = this.errorState.asReadonly();

  begin(label: string): void {
    this.labelState.set(label);
    this.pending.update((value) => value + 1);
    this.loading.set(true);
  }

  end(): void {
    this.pending.update((value) => Math.max(0, value - 1));
    if (this.pending() === 0) {
      this.loading.set(false);
      this.labelState.set('');
    }
  }

  /** Run an async unit of work with the shell skeleton shown. */
  async track<T>(label: string, work: () => Promise<T>): Promise<T | null> {
    this.begin(label);
    try {
      return await work();
    } catch (cause) {
      this.fail(cause, label);
      return null;
    } finally {
      this.end();
    }
  }

  fail(cause: unknown, context: string): void {
    this.errorState.set(describe(cause, context));
  }

  raise(error: AppError): void {
    this.errorState.set(error);
  }

  clearError(): void {
    this.errorState.set(null);
  }
}

function describe(cause: unknown, context: string): AppError {
  if (cause instanceof HttpErrorResponse) {
    const detail = extractDetail(cause);
    return {
      title: titleFor(cause.status, context),
      detail,
      code: `HTTP ${cause.status} · ${cause.url ?? 'unknown endpoint'}`,
    };
  }
  return {
    title: `${context} failed`,
    detail: cause instanceof Error ? cause.message : 'An unexpected error occurred.',
    code: 'CLIENT_ERROR',
  };
}

function titleFor(status: number, context: string): string {
  if (status === 0) {
    return 'The application server is unreachable';
  }
  if (status === 403) {
    return 'You are not authorized to perform this action';
  }
  if (status === 409) {
    return 'This action conflicts with the current state';
  }
  return `${context} failed`;
}

function extractDetail(error: HttpErrorResponse): string {
  const body: unknown = error.error;
  if (typeof body === 'string' && body.trim()) {
    return body;
  }
  if (body && typeof body === 'object' && 'detail' in body) {
    const detail = (body as { detail: unknown }).detail;
    if (typeof detail === 'string') {
      return detail;
    }
    if (Array.isArray(detail)) {
      return detail
        .map((item) =>
          item && typeof item === 'object' && 'msg' in item ? String((item as { msg: unknown }).msg) : String(item),
        )
        .join('; ');
    }
  }
  return error.message;
}
