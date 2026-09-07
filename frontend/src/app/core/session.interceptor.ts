import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';

import { readCookie } from './api';
import { TimeContextService } from './time-context.service';

const CSRF_COOKIE = 'cg_csrf';
const CSRF_HEADER = 'X-CSRF-Token';
const AS_OF_HEADER = 'X-Config-Guardian-As-Of';
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Attach the session cookie, the double-submit CSRF token, and the historical
 * browsing context to every backend request.
 *
 * The as-of header lets the API refuse writes that were issued while the user is
 * viewing a past point in time, so historical browsing can never silently
 * produce a write derived from reconstructed state.
 */
export const sessionInterceptor: HttpInterceptorFn = (request, next) => {
  if (!request.url.startsWith('/api/')) {
    return next(request);
  }

  const headers: Record<string, string> = {};
  const csrf = readCookie(CSRF_COOKIE);
  if (csrf && !SAFE_METHODS.has(request.method.toUpperCase())) {
    headers[CSRF_HEADER] = csrf;
  }

  const asOf = inject(TimeContextService).asOf();
  if (asOf) {
    headers[AS_OF_HEADER] = asOf.toISOString();
  }

  return next(request.clone({ withCredentials: true, setHeaders: headers }));
};
