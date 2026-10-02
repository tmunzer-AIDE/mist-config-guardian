import {
  ChangeDetectionStrategy,
  Component,
  computed,
  effect,
  inject,
  input,
  output,
  signal,
} from '@angular/core';
import { ChangedObject } from '../../core/change-group.model';
import { OrganizationContextService } from '../../core/organization-context.service';
import { ConfigurationDiff, DiffEntry } from '../history/diff.model';
import { DiffService } from '../history/diff.service';

@Component({
  selector: 'app-change-configuration',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="section-heading">
      <div>
        <span class="eyebrow">01 / CONFIGURATION</span>
        <h3>What changed</h3>
      </div>
      <span class="count"
        >{{ objects().length }} {{ objects().length === 1 ? 'object' : 'objects' }}</span
      >
    </div>
    @if (objects().length) {
      <label class="object-picker"
        >Configuration object
        <select
          [value]="selected()?.logical_object_id"
          (change)="chosen.set($any($event.target).value)"
        >
          @for (object of objects(); track object.logical_object_id) {
            <option [value]="object.logical_object_id">
              {{ object.object_name }} · {{ object.object_type }}
            </option>
          }
        </select>
      </label>
      @if (selected(); as object) {
        <div class="object-meta">
          <span>{{
            object.scope === 'org' ? 'Organization configuration' : 'Site configuration'
          }}</span
          ><span
            >{{ object.event }} · {{ version(object.before_version) }} →
            {{ version(object.after_version) }}</span
          >
        </div>
        @if (busy()) {
          <p class="state" role="status">Loading before and after values…</p>
        } @else if (error()) {
          <p class="state" role="alert">
            {{ error() }}
            <button class="cg-btn cg-btn--sm" (click)="retry.update(increment)">Retry</button>
          </p>
        } @else if (diff(); as comparison) {
          <p class="diff-summary">{{ comparison.summary }}</p>
          <div class="diff-table" role="table" aria-label="Configuration changes">
            <div class="diff-head" role="row">
              <span role="columnheader">Setting</span><span role="columnheader">Before</span
              ><span role="columnheader">After</span>
            </div>
            @for (entry of visibleEntries(); track entry.field) {
              <div class="diff-row" role="row">
                <div class="field" role="cell">
                  <code>{{ entry.field }}</code
                  ><small
                    >{{ entry.kind.toLowerCase() }}
                    @if (entry.secret) {
                      · redacted
                    }
                    @if (entry.secret_unknown) {
                      · comparison unavailable
                    }
                  </small>
                </div>
                <pre class="before" role="cell">{{ value(entry.before) }}</pre>
                <pre class="after" role="cell">{{ value(entry.after) }}</pre>
                @if (entry.note) {
                  <p class="entry-note">{{ entry.note }}</p>
                }
              </div>
            }
          </div>
          @if (entries().length > 8) {
            <button class="cg-btn cg-btn--link" (click)="expanded.set(!expanded())">
              {{
                expanded() ? 'Show fewer settings' : 'Show all ' + entries().length + ' settings'
              }}
            </button>
          }
          @if (comparison.truncated) {
            <p class="state">
              This comparison is truncated. Open the full comparison to inspect the available
              configuration.
            </p>
          }
        } @else {
          <p class="state">
            {{
              object.before_version_id
                ? 'No after version was captured. A before / after comparison is unavailable.'
                : 'No before version was captured. Previous values are unavailable.'
            }}
          </p>
          <div class="field-tags">
            @for (field of object.changed_fields; track field) {
              <code>{{ field }}</code>
            }
          </div>
        }
        <button class="cg-btn cg-btn--link" (click)="compare.emit(object)">
          Open full comparison →
        </button>
      }
    } @else {
      <p class="state">
        The audit was received, but no configuration versions have been linked yet.
      </p>
    }
  `,
  styleUrl: './change-configuration.scss',
})
export class ChangeConfiguration {
  readonly objects = input.required<ChangedObject[]>();
  readonly compare = output<ChangedObject>();
  private readonly orgs = inject(OrganizationContextService);
  private readonly api = inject(DiffService);
  protected readonly chosen = signal('');
  protected readonly diff = signal<ConfigurationDiff | null>(null);
  protected readonly busy = signal(false);
  protected readonly error = signal('');
  protected readonly retry = signal(0);
  protected readonly increment = (n: number) => n + 1;
  protected readonly expanded = signal(false);
  protected readonly selected = computed<ChangedObject | undefined>(
    () => this.objects().find((o) => o.logical_object_id === this.chosen()) ?? this.objects()[0],
  );
  protected readonly entries = computed<DiffEntry[]>(() => {
    const diff = this.diff();
    return diff
      ? diff.mode === 'chips'
        ? diff.entries
        : diff.sections.flatMap((s) => s.entries)
      : [];
  });
  protected readonly visibleEntries = computed(() =>
    this.expanded() ? this.entries() : this.entries().slice(0, 8),
  );
  protected readonly value = (value: string | null) =>
    value === null ? 'Not set' : value === '' ? '(empty string)' : value;
  protected readonly version = (value: number | null) =>
    value === null ? 'not captured' : `v${value}`;
  constructor() {
    effect((cleanup) => {
      const org = this.orgs.selected()?.id,
        object = this.selected();
      this.retry();
      let active = true;
      cleanup(() => {
        active = false;
      });
      this.diff.set(null);
      this.error.set('');
      this.expanded.set(false);
      this.busy.set(false);
      if (!org || !object?.before_version_id || !object.after_version_id) return;
      this.busy.set(true);
      void this.api.compare(org, object.before_version_id, object.after_version_id).then(
        (diff) => {
          if (active) {
            this.diff.set(diff);
            this.busy.set(false);
          }
        },
        () => {
          if (active) {
            this.error.set('Configuration values could not be loaded.');
            this.busy.set(false);
          }
        },
      );
    });
  }
}
