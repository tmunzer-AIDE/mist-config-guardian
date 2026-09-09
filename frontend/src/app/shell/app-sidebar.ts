import { ChangeDetectionStrategy, Component, inject, input } from '@angular/core';
import { RouterLink, RouterLinkActive } from '@angular/router';

import { AuthService } from '../core/auth.service';

interface NavItem {
  label: string;
  path: string;
  exact: boolean;
  icon: 'overview' | 'changes' | 'history' | 'restore' | 'impact' | 'settings';
}

const NAV: NavItem[] = [
  { label: 'Overview', path: '/', exact: true, icon: 'overview' },
  { label: 'Changes', path: '/changes', exact: false, icon: 'changes' },
  { label: 'Objects & versions', path: '/history', exact: false, icon: 'history' },
  { label: 'Impact', path: '/impact', exact: false, icon: 'impact' },
  { label: 'Settings', path: '/settings', exact: false, icon: 'settings' },
];

@Component({
  selector: 'app-sidebar',
  imports: [RouterLink, RouterLinkActive],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './app-sidebar.html',
  styleUrl: './app-sidebar.scss',
})
export class AppSidebar {
  /** Count of change groups with unrecovered critical impact. */
  readonly changeBadge = input(0);
  readonly buildLabel = input('');

  protected readonly auth = inject(AuthService);
  protected readonly items = NAV;
}
