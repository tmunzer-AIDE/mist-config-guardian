import { Routes } from '@angular/router';

import { authGuard } from './core/auth.guard';
import { AdministrationPage } from './features/administration/administration-page';
import { LoginPage } from './features/auth/login-page';
import { HistoryPage } from './features/history/history-page';
import { MonitoringPage } from './features/monitoring/monitoring-page';
import { OrganizationsPage } from './features/organizations/organizations-page';
import { PlaceholderPage } from './features/placeholder-page';
import { RestorePage } from './features/restores/restore-page';

export const routes: Routes = [
  {
    path: 'login',
    component: LoginPage,
  },
  {
    path: '',
    component: PlaceholderPage,
    canActivate: [authGuard],
    data: {
      title: 'Overview',
      description: 'Backup health, active change monitoring, pending approvals, and restore status.',
    },
  },
  {
    path: 'organizations',
    component: OrganizationsPage,
    canActivate: [authGuard],
  },
  {
    path: 'history',
    component: HistoryPage,
    canActivate: [authGuard],
  },
  {
    path: 'restores',
    component: RestorePage,
    canActivate: [authGuard],
  },
  {
    path: 'monitoring',
    component: MonitoringPage,
    canActivate: [authGuard],
  },
  {
    path: 'administration',
    component: AdministrationPage,
    canActivate: [authGuard],
  },
  {
    path: ':section',
    component: PlaceholderPage,
    canActivate: [authGuard],
    data: {
      title: 'Workspace',
      description: 'Feature implementation will follow the approved product specification.',
    },
  },
];
