import { HttpClient } from '@angular/common/http';
import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';

import { orgPath } from '../../core/api';
import { formatInstant } from '../../core/format';
import {
  Band,
  BAND_LABEL,
  COVERAGE_LABEL,
  GuardianInvestigation,
  GuardianRunDetail,
  GuardianRunReport,
  ObligationOutcome,
  RECOVERY_LABEL,
  ReportSection,
  RUN_KIND_LABEL,
  sourceLabel,
  Target,
} from '../../core/guardian.model';
import { OrganizationContextService } from '../../core/organization-context.service';

/**
 * One audit's Guardian investigation: the published Early and Final results,
 * each rendered section by section, and every attempt the investigation spent.
 *
 * Three things this panel refuses to do:
 *
 * - **Pass the agent's words off as the system's.** Anything the model wrote —
 *   its summary, its findings, its gaps — is labelled as the AI agent's, every
 *   time it appears, beside the deterministic sentence that does not come from it.
 * - **Show an early or failed result as a settled one.** Each tab says which
 *   kind of run it is, and an early result published by a finished investigation
 *   says that no final result is coming.
 * - **Call withheld evidence missing.** An item the agent could not cite is
 *   reported as withheld from it; the item exists and is listed in the evidence
 *   table either way.
 *
 * Reports arrive with the investigation. A single attempt's full run — its
 * steps, rejections and the evidence each turn saw — is a separate, bounded
 * read, made only when that attempt is expanded.
 *
 * Every string below can come from a provider or from the model, so all of it
 * is interpolated as text. Nothing here is bound as HTML.
 */
@Component({
  selector: 'app-guardian-panel',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <button class="cg-btn" type="button" (click)="load()" [disabled]="pending()">
      Review Guardian investigation
    </button>
    @if (pending()) {
      <p role="status">Loading the Guardian investigation…</p>
    }
    @if (message()) {
      <p role="status">{{ message() }}</p>
    }
    @if (investigation(); as investigation) {
      <section aria-label="Guardian investigation">
        <h3>Guardian investigation</h3>
        <p>{{ statusLine() }}</p>
        @if (investigation.unreadable_attempts > 0) {
          <p role="status">
            {{ investigation.unreadable_attempts }}
            {{ investigation.unreadable_attempts === 1 ? 'attempt' : 'attempts' }} could not be read
            by this build and {{ investigation.unreadable_attempts === 1 ? 'is' : 'are' }} missing
            from the lists below. This list is not complete.
          </p>
        }

        @if (tabs().length) {
          <div role="tablist" aria-label="Published results">
            @for (tab of tabs(); track tab.id) {
              <button
                class="cg-btn"
                type="button"
                role="tab"
                [attr.aria-selected]="selectedId() === tab.id"
                (click)="selectedId.set(tab.id)"
              >
                {{ label(tab) }}
              </button>
            }
          </div>
        } @else {
          <p>{{ noPublishedRun() }}</p>
        }

        @if (selected(); as run) {
          <article role="tabpanel" [attr.aria-label]="label(run)">
            <h4>{{ label(run) }}</h4>
            <p class="note">{{ kindNote(run) }}</p>
            @if (run.report.header; as header) {
              <p class="ratings">
                <strong>Peak: {{ band(header.peak) }}</strong> ·
                <strong>Current: {{ band(header.current) }}</strong>
                @if (recovery(header.recovery)) {
                  · {{ recovery(header.recovery) }}
                }
              </p>
              <p>
                Confidence: {{ header.confidence }} · Deterministic coverage:
                {{ coverage(header.coverage) }} · Sources: {{ sources(header.sources) }}
              </p>
            } @else {
              <p role="status">{{ run.report.header_note }}</p>
            }

            <h5>Summary</h5>
            @if (run.report.summary.deterministic) {
              <p>{{ run.report.summary.deterministic }}</p>
            }
            @if (run.report.summary.ai; as ai) {
              <p class="ai-label">
                <strong>AI summary · the AI agent's own words, not a verified statement</strong>
              </p>
              <p class="ai">{{ ai }}</p>
            } @else if (run.report.summary.ai_note; as note) {
              <p>{{ note }}</p>
            }

            <h5>Change</h5>
            @for (atom of run.report.change.items; track atom.id) {
              <p>
                {{ atom.id }} · {{ atom.attribute }} on {{ atom.logical_object_id }} v{{
                  atom.version
                }}
                · {{ paths(atom.paths) }}
                @if (!atom.paths_complete) {
                  · changed paths incomplete
                }
              </p>
            }
            @if (empty(run.report.change); as text) {
              <p>{{ text }}</p>
            }
            @if (omittedRows(run.report.change); as note) {
              <p>{{ note }}</p>
            }

            <h5>Coverage</h5>
            @if (run.report.coverage.coverage; as value) {
              <p>Deterministic coverage: {{ coverage(value) }}</p>
            }
            @for (row of run.report.coverage.rows.items; track $index) {
              <p>
                {{ row.atom_id }} · {{ target(row.target) }} · {{ row.resolution }} ·
                {{ row.obligation_ids.length ? row.obligation_ids.join(', ') : 'no obligation' }}
                @if (row.uncovered_paths.length) {
                  · uncovered: {{ paths(row.uncovered_paths) }}
                }
              </p>
            }
            @if (empty(run.report.coverage.rows); as text) {
              <p>{{ text }}</p>
            }
            @if (omittedRows(run.report.coverage.rows); as note) {
              <p>{{ note }}</p>
            }
            @for (item of run.report.coverage.obligations.items; track $index) {
              <p>
                {{ item.obligation.id }} · {{ item.obligation.kind }} ·
                {{ sourceLabel(item.obligation.owner) }} · {{ changeRef(item) }} ·
                {{ item.status.status }}
                @if (item.status.reason) {
                  · {{ item.status.reason }}
                }
                @if (item.status.evidence_ids.length) {
                  · {{ item.status.evidence_ids.join(', ') }}
                }
              </p>
            }
            @if (empty(run.report.coverage.obligations); as text) {
              <p>{{ text }}</p>
            }
            @if (omittedRows(run.report.coverage.obligations); as note) {
              <p>{{ note }}</p>
            }

            <h5>Devices</h5>
            @for (device of run.report.devices.items; track device.mac) {
              <p>
                {{ device.name || device.mac }} · {{ device.mac }} · monitoring
                {{ device.status }} · deployment {{ device.deployment ?? 'unknown' }} · peak
                {{ device.peak ?? 'not set' }} · current {{ device.current ?? 'not set' }}
              </p>
            }
            @if (empty(run.report.devices); as text) {
              <p>{{ text }}</p>
            }
            @if (omittedDevices(run.report.devices); as note) {
              <p>{{ note }}</p>
            }

            <h5>Impacted devices</h5>
            @for (device of run.report.impacted.items; track device.mac) {
              <p>
                {{ device.name || device.mac }} · {{ device.mac }} · site {{ device.site_id }} ·
                peak {{ device.peak }} · current {{ device.current }}
              </p>
            }
            @if (empty(run.report.impacted); as text) {
              <p>{{ text }}</p>
            }
            @if (omittedImpacted(run.report.impacted); as note) {
              <p>{{ note }}</p>
            }

            <h5>Findings</h5>
            @for (finding of run.report.findings.items; track $index) {
              <p>
                <strong>{{ sourceLabel(finding.source) }}</strong> · {{ finding.severity }} ·
                {{ finding.text }}
                @if (finding.evidence_ids.length) {
                  · cites {{ finding.evidence_ids.join(', ') }}
                }
              </p>
            }
            @if (empty(run.report.findings); as text) {
              <p>{{ text }}</p>
            }
            @if (omittedRows(run.report.findings); as note) {
              <p>{{ note }}</p>
            }

            <h5>Evidence</h5>
            <div class="scroll">
              <table>
                <caption>
                  Evidence collected by this attempt
                </caption>
                <thead>
                  <tr>
                    <th>E-id</th>
                    <th>Source</th>
                    <th>Collection</th>
                    <th>Details</th>
                  </tr>
                </thead>
                <tbody>
                  @for (item of run.report.evidence.items; track item.id) {
                    <tr>
                      <td>{{ item.id }}</td>
                      <td>{{ sourceLabel(item.source) }}<br />{{ item.kind }}</td>
                      <td>
                        {{ item.collection }} · {{ item.representation }}
                        @if (!item.citable) {
                          <br />Not citable
                        }
                      </td>
                      <td>
                        {{ item.title }}<br />{{ at(item.captured_at) }}
                        @if (item.detail) {
                          <br />{{ item.detail }}
                        }
                      </td>
                    </tr>
                  }
                </tbody>
              </table>
            </div>
            @if (empty(run.report.evidence); as text) {
              <p>{{ text }}</p>
            }
            @if (omittedRows(run.report.evidence); as note) {
              <p>{{ note }}</p>
            }

            <h5>Gaps</h5>
            @for (gap of run.report.gaps.items; track $index) {
              <p><strong>{{ sourceLabel(gap.source) }}</strong> · {{ gap.text }}</p>
            }
            @if (empty(run.report.gaps); as text) {
              <p>{{ text }}</p>
            }
            @if (omittedRows(run.report.gaps); as note) {
              <p>{{ note }}</p>
            }
          </article>
        }

        <h4>Attempts</h4>
        @for (attempt of investigation.attempts; track attempt.id) {
          <article class="attempt">
            <button
              class="cg-btn"
              type="button"
              [attr.aria-expanded]="expandedId() === attempt.id"
              (click)="expand(attempt.id)"
            >
              {{ kindLabel(attempt.kind) }} · attempt {{ attempt.attempt }} · {{ attempt.state }} ·
              {{ attempt.published ? 'published' : 'not published' }}
            </button>
            @if (attempt.failure_reason) {
              <p>{{ attempt.failure_reason }}</p>
            }
            <p>
              {{ attempt.budget.model_turns }} model turns · {{ attempt.budget.mcp_calls }} MCP
              calls · {{ attempt.budget.rule_reads }} rule reads
            </p>
            @if (expandedId() === attempt.id) {
              @if (runPending()) {
                <p role="status">Loading this attempt…</p>
              }
              @if (runMessage()) {
                <p role="status">{{ runMessage() }}</p>
              }
              @if (runDetail(); as detail) {
                @for (step of detail.steps; track $index) {
                  <p>
                    Turn {{ step.turn }} · {{ step.action }}
                    @if (step.tool) {
                      · {{ step.tool }}
                    }
                    @if (step.evidence_id) {
                      · {{ step.evidence_id }} ({{ step.collection }})
                    }
                    @if (step.rejection) {
                      · rejected: {{ step.rejection }}
                      @if (step.detail) {
                        — {{ step.detail }}
                      }
                    }
                  </p>
                  <p class="ids">
                    Shown to the AI agent: {{ idList(step.visible_evidence_ids) }}
                    @if (hasIds(step.withheld_evidence_ids)) {
                      · Withheld from the AI agent, which could not cite it:
                      {{ idList(step.withheld_evidence_ids) }}
                    }
                  </p>
                  @if (step.output) {
                    <p class="ai-label"><strong>AI agent output · redacted and truncated</strong></p>
                    <p class="ai">{{ step.output }}</p>
                  }
                }
                @if (!detail.steps.length) {
                  <p>This attempt recorded no model turn: {{ noSteps(detail) }}</p>
                }
              }
            }
          </article>
        }
        @if (!investigation.attempts.length) {
          <p>No attempt is recorded for this investigation.</p>
        }
      </section>
    }
  `,
  styles: `
    :host { display: block; margin-top: 1rem; }
    section { border-top: 1px solid var(--border); margin-top: 1rem; padding-top: 1rem; overflow-wrap: anywhere; }
    h3, h4, h5 { margin: .75rem 0; } p { margin: .5rem 0; line-height: 1.5; }
    .note { font-weight: 600; } .ai-label { opacity: .9; } .ai { font-style: italic; }
    .ids { opacity: .8; font-size: .8rem; } .attempt { padding: .5rem 0; }
    .scroll { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; margin: .75rem 0; }
    th, td { padding: .5rem; text-align: left; border-bottom: 1px solid var(--border); vertical-align: top; }
    caption { text-align: left; padding: .5rem; }
    [role='tablist'] { display: flex; flex-wrap: wrap; gap: .5rem; margin: .75rem 0; }
  `,
})
export class GuardianPanel {
  readonly groupId = input.required<string>();

  private readonly organizations = inject(OrganizationContextService);
  private readonly http = inject(HttpClient);

  protected readonly pending = signal(false);
  protected readonly message = signal('');
  protected readonly investigation = signal<GuardianInvestigation | null>(null);
  protected readonly selectedId = signal<string | null>(null);
  protected readonly expandedId = signal<string | null>(null);
  protected readonly runDetail = signal<GuardianRunDetail | null>(null);
  protected readonly runPending = signal(false);
  protected readonly runMessage = signal('');

  // Answers for a change group, or an organization, the user has moved off must
  // not land in the panel now on screen.
  private request = 0;
  private runRequest = 0;

  protected readonly sourceLabel = sourceLabel;
  protected readonly at = (value: string) => formatInstant(new Date(value));
  protected readonly recovery = (value: keyof typeof RECOVERY_LABEL) => RECOVERY_LABEL[value];
  protected readonly coverage = (value: keyof typeof COVERAGE_LABEL) => COVERAGE_LABEL[value];
  protected readonly kindLabel = (kind: 'early' | 'final') => RUN_KIND_LABEL[kind];
  /** A severity band in words. The bare enum never appears beside a worded verdict. */
  protected readonly band = (value: Band) => BAND_LABEL[value];

  /** Published runs, early first, so the Final tab is the later word when there is one. */
  protected readonly tabs = computed(() => {
    const runs = this.investigation()?.runs ?? [];
    return [...runs].sort((left, right) => (left.kind === right.kind ? 0 : left.kind === 'early' ? -1 : 1));
  });

  protected readonly selected = computed(() => {
    const tabs = this.tabs();
    return tabs.find((run) => run.id === this.selectedId()) ?? tabs[tabs.length - 1] ?? null;
  });

  protected readonly statusLine = computed(() => {
    const root = this.investigation()?.root;
    if (!root) {
      return '';
    }
    const attempts = `${root.attempts.early} early and ${root.attempts.final} final ${
      root.attempts.early + root.attempts.final === 1 ? 'attempt' : 'attempts'
    }`;
    const state = root.status === 'done' ? 'Finished' : 'Still investigating';
    const reason = root.status_reason ? ` · ${root.status_reason}` : '';
    const next =
      root.status === 'waiting' && root.next_check_at ? ` · next check ${this.at(root.next_check_at)}` : '';
    // An anchor the audit did not carry means the timing is receipt-based, which
    // is worth saying rather than presenting the change time as observed.
    const anchor = root.anchor_known ? '' : ' · change time not carried by the audit; receipt time used';
    return `${state} · ${attempts}${reason}${next}${anchor}`;
  });

  constructor() {
    effect(() => {
      this.groupId();
      this.organizations.selected()?.id;
      this.request++;
      this.runRequest++;
      this.investigation.set(null);
      this.selectedId.set(null);
      this.expandedId.set(null);
      this.runDetail.set(null);
      this.runMessage.set('');
      this.message.set('');
      this.pending.set(false);
      this.runPending.set(false);
    });
  }

  protected label(run: GuardianRunReport): string {
    return `${RUN_KIND_LABEL[run.kind]} · attempt ${run.attempt}`;
  }

  /** What this tab's run is, said before its numbers are read. */
  protected kindNote(run: GuardianRunReport): string {
    const root = this.investigation()?.root;
    const parts: string[] = [];
    if (run.kind === 'early') {
      parts.push(
        root?.final_run_id
          ? 'This is the early result. A final result was published and is shown on its own tab.'
          : root?.status === 'done'
            ? `This is an early result and it is the last one: the investigation ended without publishing a final result${
                root.status_reason ? ` (${root.status_reason})` : ''
              }.`
            : 'This is an early result, taken while the investigation was still running. It may be superseded by a final result.',
      );
    } else {
      parts.push('This is the final result of the investigation.');
    }
    if (run.state !== 'succeeded') {
      parts.push(`This attempt is ${run.state} rather than succeeded, so it is incomplete.`);
    }
    return parts.join(' ');
  }

  /** Why no tab is shown, from the root rather than from a default sentence. */
  protected noPublishedRun(): string {
    const root = this.investigation()?.root;
    if (!root) {
      return '';
    }
    if (root.status === 'waiting') {
      return 'No result has been published yet; the investigation is still running.';
    }
    return `The investigation finished without publishing a result${
      root.status_reason ? `: ${root.status_reason}` : '.'
    }`;
  }

  protected noSteps(detail: GuardianRunDetail): string {
    return detail.failure_reason ?? `the attempt is ${detail.state} and used ${detail.budget.model_turns} model turns`;
  }

  /** An empty section's own explanation; a non-empty one has nothing to explain. */
  protected empty<T>(section: ReportSection<T>): string | null {
    return section.items.length ? null : section.explanation;
  }

  /**
   * What a section left out. The report shows the first 50 rows and folds the
   * rest into `omitted`, so a section that says nothing about it would offer 50
   * rows as the whole set.
   */
  protected omittedRows<T>(section: ReportSection<T>): string | null {
    const omitted = section.omitted;
    return omitted > 0
      ? `${omitted} further ${omitted === 1 ? 'row is' : 'rows are'} not shown here.`
      : null;
  }

  /**
   * Devices this section does not list. The count mixes two causes — monitoring
   * counted some in a digest without recording them, and the rest fall past the
   * display limit — and naming only one of them would be false for the others.
   */
  protected omittedDevices<T>(section: ReportSection<T>): string | null {
    const omitted = section.omitted;
    if (omitted <= 0) {
      return null;
    }
    return (
      `${omitted} further ${omitted === 1 ? 'device is' : 'devices are'} not listed here: ` +
      'monitoring counted them in a digest without recording them, or they fall beyond the rows this section shows.'
    );
  }

  /** The same two causes, for the impacted devices the verdict named. */
  protected omittedImpacted<T>(section: ReportSection<T>): string | null {
    const omitted = section.omitted;
    if (omitted <= 0) {
      return null;
    }
    return (
      `${omitted} further impacted ${omitted === 1 ? 'device is' : 'devices are'} not named here: ` +
      'this attempt did not record them individually, or they fall beyond the rows this section shows.'
    );
  }

  protected paths(paths: string[][]): string {
    return paths.length ? paths.map((path) => path.join('.')).join(', ') : 'no path recorded';
  }

  protected target(target: Target): string {
    const parts = [target.device_mac, target.site_id, target.port_id, target.wlan_id].filter(
      (value): value is string => !!value,
    );
    return parts.length ? parts.join(' · ') : 'the organization';
  }

  /** The core `input` obligation names no atom, because the atom is what it could not build. */
  protected changeRef(item: ObligationOutcome): string {
    return item.obligation.change_ref ?? 'no change atom · an input this attempt never saw in full';
  }

  /** E-ids as one line; a turn that saw none says so rather than printing nothing. */
  protected idList(ids: string[] | undefined): string {
    return ids?.length ? ids.join(', ') : 'none';
  }

  protected hasIds(ids: string[] | undefined): boolean {
    return !!ids?.length;
  }

  protected sources(sources: string[]): string {
    return sources.length ? sources.map(sourceLabel).join(', ') : 'none recorded';
  }

  protected async load(): Promise<void> {
    const organization = this.organizations.selected()?.id;
    if (!organization) {
      return;
    }
    const request = ++this.request;
    this.pending.set(true);
    this.message.set('');
    this.investigation.set(null);
    this.expandedId.set(null);
    this.runDetail.set(null);
    try {
      const investigation = await firstValueFrom(
        this.http.get<GuardianInvestigation | null>(
          orgPath(organization, `/change-groups/${this.groupId()}/guardian`),
        ),
      );
      if (request !== this.request) {
        return;
      }
      this.investigation.set(investigation);
      if (!investigation) {
        this.message.set('No Guardian investigation was recorded for this change.');
        return;
      }
      // The later word is the one to open on; the early tab stays reachable.
      this.selectedId.set(this.tabs()[this.tabs().length - 1]?.id ?? null);
    } catch (cause) {
      if (request === this.request) {
        this.message.set(
          isNotFound(cause)
            ? 'No Guardian investigation was recorded for this change.'
            : 'The Guardian investigation could not be loaded. This is not a clean result.',
        );
      }
    } finally {
      if (request === this.request) {
        this.pending.set(false);
      }
    }
  }

  /**
   * Expand one attempt and read its full run.
   *
   * The investigation carries rendered reports for published runs only, and no
   * steps at all, so the turns, rejections and the evidence each turn saw are
   * fetched here rather than being held for every attempt in advance.
   */
  protected async expand(id: string): Promise<void> {
    const organization = this.organizations.selected()?.id;
    if (this.expandedId() === id) {
      this.expandedId.set(null);
      return;
    }
    this.expandedId.set(id);
    this.runDetail.set(null);
    this.runMessage.set('');
    if (!organization) {
      return;
    }
    const request = ++this.runRequest;
    this.runPending.set(true);
    try {
      const detail = await firstValueFrom(
        this.http.get<GuardianRunDetail>(
          orgPath(organization, `/change-groups/${this.groupId()}/guardian/runs/${id}`),
        ),
      );
      if (request === this.runRequest) {
        this.runDetail.set(detail);
      }
    } catch (cause) {
      if (request === this.runRequest) {
        this.runMessage.set(
          isNotFound(cause)
            ? 'This attempt is no longer available: its stored run could not be read.'
            : 'This attempt could not be loaded.',
        );
      }
    } finally {
      if (request === this.runRequest) {
        this.runPending.set(false);
      }
    }
  }
}

function isNotFound(cause: unknown): boolean {
  return typeof cause === 'object' && cause !== null && (cause as { status?: number }).status === 404;
}
