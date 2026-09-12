import { inject } from '@angular/core';
import { RedirectFunction, Router, Routes } from '@angular/router';

import { authGuard, historyAccessGuard } from './core/auth.guard';

/** Send `/<page>/<tab>` to `/<page>?tab=<tab>`, the one route that mounts the page. */
function tabRedirect(page: string): RedirectFunction {
  return ({ params }) => inject(Router).createUrlTree([page], { queryParams: { tab: params['tab'] } });
}

export const routes: Routes = [
  {
    path: 'login',
    loadComponent: () => import('./features/auth/login-page').then((m) => m.LoginPage),
    title: 'Sign in · Config Guardian',
  },
  {
    path: '',
    canActivate: [authGuard],
    loadComponent: () => import('./features/overview/overview-page').then((m) => m.OverviewPage),
    title: 'Overview · Config Guardian',
  },
  {
    path: 'changes',
    canActivate: [authGuard],
    loadComponent: () => import('./features/changes/changes-page').then((m) => m.ChangesPage),
    title: 'Changes · Config Guardian',
  },
  {
    path: 'history',
    canActivate: [authGuard, historyAccessGuard],
    runGuardsAndResolvers: 'paramsOrQueryParamsChange',
    loadComponent: () => import('./features/history/history-page').then((m) => m.HistoryPage),
    title: 'Configuration library · Config Guardian',
  },
  ...['restore', 'history/restore'].map(path => ({
    path,
    redirectTo: (({ queryParams, fragment }) => inject(Router).createUrlTree(
      ['/history'], { queryParams: { ...queryParams, restore: '1' }, fragment: fragment ?? undefined },
    )) as RedirectFunction,
  })),
  {
    path: 'impact',
    canActivate: [authGuard],
    loadComponent: () => import('./features/impact/site-impact-page').then((m) => m.SiteImpactPage),
    title: 'Impact · Config Guardian',
  },
  {
    path: 'impact/sessions',
    canActivate: [authGuard],
    loadComponent: () => import('./features/impact/impact-page').then((m) => m.ImpactPage),
    title: 'Impact evidence · Config Guardian',
  },
  {
    path: 'search',
    canActivate: [authGuard],
    loadComponent: () => import('./features/search/search-page').then((m) => m.SearchPage),
    title: 'Search · Config Guardian',
  },
  {
    path: 'account',
    canActivate: [authGuard],
    loadComponent: () => import('./features/account/account-page').then((m) => m.AccountPage),
    title: 'Your account · Config Guardian',
  },
  {
    path: 'settings',
    canActivate: [authGuard],
    loadComponent: () => import('./features/settings/settings-page').then((m) => m.SettingsPage),
    title: 'Settings · Config Guardian',
  },
  {
    // The shell's organization and user menus link straight to a tab, so the
    // tab is addressable as a path segment as well. It redirects to the query
    // form rather than mounting the page a second way: two route entries for
    // one page would remount it on every tab switch between them, refetching,
    // closing dialogs and dropping keyboard focus.
    path: 'settings/:tab',
    redirectTo: tabRedirect('/settings'),
  },
  {
    path: 'account/:tab',
    redirectTo: tabRedirect('/account'),
  },
  {
    // Unauthenticated by design: the invitation token is the credential, and
    // the invitee has no account to sign in with yet. It must precede the
    // wildcard, which would otherwise redirect it to the dashboard.
    path: 'accept-invitation',
    loadComponent: () =>
      import('./features/auth/accept-invitation-page').then((m) => m.AcceptInvitationPage),
    title: 'Accept invitation · Config Guardian',
  },
  { path: '**', redirectTo: '' },
];
