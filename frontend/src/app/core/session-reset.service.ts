import { inject, Injectable } from '@angular/core';

import { AccountService } from '../features/account/account.service';
import { MonitoringService } from '../features/impact/monitoring.service';
import { AiAssistService } from '../features/history/ai-assist.service';
import { AuthService } from './auth.service';
import { ChangeGroupService } from './change-group.service';
import { NotificationService } from './notification.service';
import { OrganizationContextService } from './organization-context.service';
import { OverviewService } from './overview.service';
import { SearchService } from './search.service';
import { StepUpService } from './step-up.service';
import { TimeContextService } from './time-context.service';
import { TimelineService } from './timeline.service';

/**
 * Forget everything a session owned.
 *
 * Signing out is not only an authentication change: the organization list,
 * the notification feed, the overview, the change groups, the timeline, the
 * search results and the account panels were all read as that user, for
 * organizations the next one may not be able to see. One place resets them so
 * a deliberate sign-out and a session the server has revoked leave the
 * application in the same state — and each reset discards its own reads still
 * in flight, which would otherwise answer into the next session. That includes
 * a request suspended behind an unanswered second-factor prompt, which would
 * otherwise be replayed on the next session's code.
 */
@Injectable({ providedIn: 'root' })
export class SessionResetService {
  private readonly auth = inject(AuthService);
  private readonly organizations = inject(OrganizationContextService);
  private readonly notifications = inject(NotificationService);
  private readonly overview = inject(OverviewService);
  private readonly changeGroups = inject(ChangeGroupService);
  private readonly timeline = inject(TimelineService);
  private readonly monitoring = inject(MonitoringService);
  private readonly account = inject(AccountService);
  private readonly ai = inject(AiAssistService);
  private readonly search = inject(SearchService);
  private readonly stepUp = inject(StepUpService);
  private readonly time = inject(TimeContextService);

  clear(): void {
    this.auth.forgetSession();
    this.organizations.reset();
    this.notifications.reset();
    this.overview.reset();
    this.changeGroups.reset();
    this.timeline.reset();
    this.monitoring.reset();
    this.account.reset();
    // Resolved once per session, and administrator-only: a viewer must not
    // inherit the previous administrator's answer about what AI can do.
    this.ai.reset();
    this.search.reset();
    // An unanswered code prompt belongs to the session that is ending, as do
    // the requests suspended behind it.
    this.stepUp.reset();
    this.time.returnToNow();
  }
}
