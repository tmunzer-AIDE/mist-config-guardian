import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, throwError } from 'rxjs';

import { readCookie } from './api';
import { AuthService } from './auth.service';
import { SessionResetService } from './session-reset.service';
import { TimeContextService } from './time-context.service';

const CSRF_COOKIE = 'cg_csrf';
const CSRF_HEADER = 'X-CSRF-Token';
const AS_OF_HEADER = 'X-Config-Guardian-As-Of';
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Endpoints whose own answer is 401.
 *
 * Signing in with the wrong password, or resolving a session that turns out
 * not to exist, is answered by the page that asked. Treating those as a
 * revoked session would sign the user out of a sign-in attempt, and — since
 * the redirect target itself calls them — could loop.
 */
const AUTH_ENDPOINTS = /^\/api\/v\d+\/auth\//;

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

  const auth = inject(AuthService);
  const reset = inject(SessionResetService);
  const router = inject(Router);
  // Which session issued this request. A request can outlive the session that
  // made it: without this, a 401 answering after someone has signed in again
  // would throw the new session out on the old one's behalf.
  const issuedBy = auth.session();

  return next(request.clone({ withCredentials: true, setHeaders: headers })).pipe(
    catchError((cause: unknown) => {
      // The server says this session is gone — revoked from another device,
      // expired, or signed out elsewhere. Staying in the authenticated shell
      // would leave every page failing with no way out, so the browser agrees
      // and returns to sign-in. Only while it still believes it is signed in,
      // which makes this happen once rather than on every failing request.
      if (
        cause instanceof HttpErrorResponse &&
        cause.status === 401 &&
        !AUTH_ENDPOINTS.test(request.url) &&
        auth.isAuthenticated() &&
        auth.session() === issuedBy
      ) {
        const next = router.url;
        reset.clear();
        void router.navigate(['/login'], {
          queryParams: next && next !== '/login' ? { next } : {},
        });
      }
      return throwError(() => cause);
    }),
  );
};
