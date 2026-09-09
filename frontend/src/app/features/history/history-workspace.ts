import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';

import { AuthService } from '../../core/auth.service';

/** Version comparison and restore planning share one navigation workspace. */
@Component({
  selector: 'app-history-workspace',
  imports: [RouterLink, RouterLinkActive, RouterOutlet],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <header class="workspace-head">
      <h1>History &amp; Restore</h1>
      <nav aria-label="History and restore">
        <a routerLink="/history" routerLinkActive="active"
          [routerLinkActiveOptions]="{ paths: 'exact', queryParams: 'ignored', matrixParams: 'ignored', fragment: 'ignored' }"
          ariaCurrentWhenActive="page">Versions</a>
        @if (auth.can('operator')) {
          <a routerLink="/history/restore" routerLinkActive="active"
            ariaCurrentWhenActive="page">Restore plans &amp; activity</a>
        }
      </nav>
    </header>
    <div class="workspace-content"><router-outlet /></div>
  `,
  styleUrl: './history-workspace.scss',
})
export class HistoryWorkspace {
  protected readonly auth = inject(AuthService);
}
