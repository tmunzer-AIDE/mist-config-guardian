import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';
import { formatInstant } from '../../core/format';
import { MonitoringSession } from './monitoring.model';

export function configurationTimeline(session: MonitoringSession) {
  const entries: {
    key: string;
    at: string;
    received: string | null;
    label: string;
    source: string;
  }[] = [];
  for (const change of session.change_groups ?? []) {
    if (change.occurred_at)
      entries.push({
        key: 'audit:' + change.id,
        at: change.occurred_at,
        received: null,
        label: change.title,
        source: 'Mist audit',
      });
  }
  for (const event of session.timeline ?? [])
    entries.push({
      key: event.key,
      at: event.occurred_at,
      received: event.received_at,
      label: event.event_type.replaceAll('_', ' '),
      source: event.event_type.startsWith('ASSESSMENT_')
        ? 'Guardian assessment'
        : 'Mist device event',
    });
  if (
    session.change_triggered_at &&
    !session.timeline?.some((event) => event.event_type.includes('CONFIG_CHANGED'))
  )
    entries.push({
      key: 'trigger',
      at: session.change_triggered_at,
      received: null,
      label: 'Configuration change reported',
      source: 'Stored session',
    });
  if (
    session.config_applied_at &&
    !session.timeline?.some((event) => event.event_type.endsWith('_CONFIGURED'))
  )
    entries.push({
      key: 'configured',
      at: session.config_applied_at,
      received: null,
      label: 'Device configuration confirmed',
      source: 'Stored session',
    });
  for (const [index, comparison] of (session.device_comparisons ?? []).entries()) {
    entries.push({
      key: 'capture:' + index,
      at: comparison.baseline.captured_at,
      received: null,
      label: 'Initial operational state captured',
      source: 'Guardian collection',
    });
    if (comparison.followup)
      entries.push({
        key: 'followup:' + index,
        at: comparison.followup.captured_at,
        received: null,
        label: 'First operational comparison captured',
        source: 'Guardian collection',
      });
    if (comparison.recovered_at)
      entries.push({
        key: 'recovered:' + index,
        at: comparison.recovered_at,
        received: null,
        label: 'Operational recovery observed',
        source: 'Guardian collection',
      });
  }
  if (session.completed_at)
    entries.push({
      key: 'end',
      at: session.completed_at,
      received: null,
      label: 'Monitoring ended',
      source: 'Guardian',
    });
  return entries.sort((a, b) => Date.parse(a.at) - Date.parse(b.at) || a.key.localeCompare(b.key));
}

@Component({
  selector: 'app-configuration-timeline',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="cg-card timeline">
      <h3>Configuration timeline</h3>
      <p>
        Only observed events are shown. Event time and webhook receipt time can differ; missing
        deployment stages are not inferred.
      </p>
      <ol>
        @for (entry of entries(); track entry.key) {
          <li>
            <time [attr.datetime]="entry.at" [title]="entry.at">{{ at(entry.at) }}</time>
            <div>
              <strong>{{ entry.label }}</strong>
              <small
                >{{ entry.source }}
                @if (entry.received) {
                  · Received {{ at(entry.received) }}
                }
              </small>
            </div>
          </li>
        } @empty {
          <li>No lifecycle events were stored for this session.</li>
        }
      </ol>
    </section>
  `,
  styles: `
    :host {
      display: block;
      min-width: 0;
    }
    .timeline {
      padding: 20px;
    }
    h3 {
      margin: 0 0 10px;
      font-size: 16px;
    }
    p,
    small {
      color: var(--ink-soft);
      font-size: 12px;
    }
    ol {
      list-style: none;
      margin: 0;
      padding: 0;
      max-height: 360px;
      overflow: auto;
    }
    li {
      display: grid;
      grid-template-columns: 150px minmax(0, 1fr);
      gap: 14px;
      padding: 12px 0;
      border-top: 1px solid var(--hairline);
    }
    time {
      font: 11px var(--font-mono);
      color: var(--ink-soft);
    }
    strong {
      font-size: 12px;
      overflow-wrap: anywhere;
    }
    small {
      display: block;
      margin-top: 5px;
    }
    @media (max-width: 600px) {
      li {
        grid-template-columns: 1fr;
        gap: 6px;
      }
    }
  `,
})
export class ConfigurationTimeline {
  readonly session = input.required<MonitoringSession>();
  protected readonly entries = computed(() => configurationTimeline(this.session()));
  protected readonly at = (at: string) => {
    const date = new Date(at);
    return formatInstant(date).replace(
      'Z',
      ':' + String(date.getUTCSeconds()).padStart(2, '0') + 'Z',
    );
  };
}
