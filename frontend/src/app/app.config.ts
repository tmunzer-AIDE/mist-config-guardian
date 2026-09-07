import { provideHttpClient, withInterceptors } from '@angular/common/http';
import {
  ApplicationConfig,
  inject,
  provideAppInitializer,
  provideBrowserGlobalErrorListeners,
} from '@angular/core';
import { provideRouter, withComponentInputBinding, withInMemoryScrolling } from '@angular/router';

import { routes } from './app.routes';
import { AuthService } from './core/auth.service';
import { sessionInterceptor } from './core/session.interceptor';

export const appConfig: ApplicationConfig = {
  providers: [
    provideBrowserGlobalErrorListeners(),
    provideHttpClient(withInterceptors([sessionInterceptor])),
    provideRouter(routes, withComponentInputBinding(), withInMemoryScrolling({ scrollPositionRestoration: 'top' })),
    // Resolve the cookie session before the first route activates so a reload
    // lands on the requested page instead of bouncing through the sign-in form.
    provideAppInitializer(() => inject(AuthService).restore()),
  ],
};
