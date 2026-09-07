import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';

import { formatInstant } from '../../core/format';
import { ComponentStatus, SystemHealthService } from '../../core/system-health.service';
import { Tone } from '../../core/tone';

/**
 * The service health panel.
 *
 * Every status is carried by its label as well as its colour, because this is
 * the panel someone reads when they already suspect something is wrong and a
 * dot on its own would not survive a screenshot pasted into a ticket.
 */
@Component({
  selector: 'app-health-tab',
  imports: [],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './health-tab.html',
  styleUrl: './health-tab.scss',
})
export class HealthTab {
  private readonly service = inject(SystemHealthService);

  protected readonly refreshing = signal(false);
  protected readonly health = this.service.health;

  protected readonly rows = computed(() =>
    (this.health()?.components ?? []).map((component) => ({
      key: component.key,
      label: component.label,
      status: component.status,
      statusLabel: LABELS[component.status],
      tone: toneFor(component.status),
      detail: component.detail,
      latency: component.latency_ms === null ? '' : `${component.latency_ms} ms`,
    })),
  );

  protected readonly aggregate = computed(() => {
    const current = this.health();
    if (!current) {
      return null;
    }
    const degraded = current.components.filter((item) => item.status !== 'ok').length;
    return {
      status: current.status,
      statusLabel: LABELS[current.status],
      tone: toneFor(current.status),
      summary:
        degraded === 0
          ? 'Every component is responding normally.'
          : `${degraded} of ${current.components.length} components ${degraded === 1 ? 'is' : 'are'} not healthy.`,
      checkedAt: formatInstant(new Date(current.checked_at)),
    };
  });

  protected async refresh(): Promise<void> {
    if (this.refreshing()) {
      return;
    }
    this.refreshing.set(true);
    try {
      await this.service.load();
    } finally {
      this.refreshing.set(false);
    }
  }
}

const LABELS: Record<ComponentStatus, string> = {
  ok: 'HEALTHY',
  degraded: 'DEGRADED',
  failed: 'FAILED',
};

function toneFor(status: ComponentStatus): Tone {
  switch (status) {
    case 'ok':
      return 'ok';
    case 'degraded':
      return 'warn';
    default:
      return 'crit';
  }
}
