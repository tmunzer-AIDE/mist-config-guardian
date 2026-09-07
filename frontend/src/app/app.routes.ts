import { Routes } from '@angular/router';

import { authGuard, roleGuard } from './core/auth.guard';

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
    canActivate: [authGuard],
    loadComponent: () => import('./features/history/history-page').then((m) => m.HistoryPage),
    title: 'History · Config Guardian',
  },
  {
    path: 'restore',
    canActivate: [roleGuard('operator')],
    loadComponent: () => import('./features/restore/restore-page').then((m) => m.RestorePage),
    title: 'Restore · Config Guardian',
  },
  {
    path: 'impact',
    canActivate: [authGuard],
    loadComponent: () => import('./features/impact/impact-page').then((m) => m.ImpactPage),
    title: 'Impact · Config Guardian',
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
  { path: '**', redirectTo: '' },
];
