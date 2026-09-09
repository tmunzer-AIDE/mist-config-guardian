import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';

import { AuthService } from './auth.service';
import { UserRole } from './auth.service';

/** Require an authenticated session, remembering where the user was headed. */
export const authGuard: CanActivateFn = (_route, state) => {
  const auth = inject(AuthService);
  if (auth.isAuthenticated()) {
    return true;
  }
  return inject(Router).createUrlTree(['/login'], { queryParams: { next: state.url } });
};

/** Require at least the given application role. */
export function roleGuard(minimum: UserRole): CanActivateFn {
  return () => {
    const auth = inject(AuthService);
    if (!auth.isAuthenticated()) {
      return inject(Router).createUrlTree(['/login']);
    }
    return auth.can(minimum) ? true : inject(Router).createUrlTree(['/']);
  };
}

/** The shared history route needs an operator only when it opens restore context. */
export const historyAccessGuard: CanActivateFn = (route, state) => {
  const restoreContext = route.queryParamMap.get('restore') === '1' ||
    ['versions', 'operation', 'changeGroup', 'step', 'compensate'].some(key => route.queryParamMap.has(key));
  return restoreContext ? roleGuard('operator')(route, state) : true;
};
