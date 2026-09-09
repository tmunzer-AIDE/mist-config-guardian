import { ChangeDetectionStrategy, Component, computed, input, linkedSignal } from '@angular/core';

const PAGE_SIZE = 50;

/** Only the visible page is formatted; the parent mounts this on expansion. */
@Component({
  selector: 'app-telemetry-capture',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <h4>{{ label() }}</h4>
    @if (error()) { <p class="error">{{ error() }}</p> }
    @if (value() === null) { <p>{{ emptyLabel() }}</p> }
    @else if (!total()) { <p>No records in this capture.</p> }
    @else {
      <p class="count" aria-live="polite">Records {{ start() + 1 }}–{{ end() }} of {{ total() }}</p>
      @if (total() > pageSize) {
        <nav [attr.aria-label]="label() + ' records'">
          <button type="button" (click)="page.set(0)" [disabled]="page() === 0">First</button>
          <button type="button" (click)="page.set(page() - 1)" [disabled]="page() === 0">Previous</button>
          <button type="button" (click)="page.set(page() + 1)" [disabled]="end() === total()">Next</button>
          <button type="button" (click)="page.set(lastPage())" [disabled]="end() === total()">Last</button>
        </nav>
      }
      <div class="records" tabindex="0" role="region" [attr.aria-label]="label() + ' telemetry'">
        <table>
          <thead><tr>@for (column of display().columns; track column) { <th scope="col">{{ column }}</th> }</tr></thead>
          <tbody>@for (row of display().rows; track $index) {
            <tr>@for (cell of row; track $index) { <td>{{ cell }}</td> }</tr>
          }</tbody>
        </table>
      </div>
    }
  `,
  styles: `
    :host { display:block; min-width:0; }
    h4 { margin:14px 0 8px; } .count { color:var(--ink-soft); font-size:12px; }
    nav { display:flex; flex-wrap:wrap; gap:6px; margin:8px 0; }
    button { border:1px solid var(--hairline); border-radius:4px; background:var(--surface); color:var(--ink); padding:5px 10px; cursor:pointer; }
    button:disabled { opacity:.45; cursor:default; }
    .records { overflow:auto; max-height:360px; border:1px solid var(--hairline); }
    table { border-collapse:collapse; font-size:12px; width:100%; }
    th, td { padding:8px; border-bottom:1px solid var(--hairline); text-align:left; vertical-align:top; }
    th { position:sticky; top:0; background:var(--surface-sunken); }
    td { min-width:100px; max-width:320px; overflow-wrap:anywhere; white-space:pre-wrap; }
    .error { color:var(--tone-warning-ink); }
  `,
})
export class TelemetryCapture {
  readonly label = input.required<string>();
  readonly value = input.required<Record<string, unknown> | Record<string, unknown>[] | null>();
  readonly error = input<string>();
  readonly emptyLabel = input('Unavailable');
  protected readonly pageSize = PAGE_SIZE;
  protected readonly page = linkedSignal({ source: this.value, computation: () => 0 });
  private readonly records = computed(() => {
    const value = this.value();
    return value === null ? [] : Array.isArray(value) ? value : [value];
  });
  protected readonly total = computed(() => this.records().length);
  protected readonly lastPage = computed(() => Math.max(0, Math.ceil(this.total() / PAGE_SIZE) - 1));
  protected readonly start = computed(() => this.page() * PAGE_SIZE);
  protected readonly end = computed(() => Math.min(this.start() + PAGE_SIZE, this.total()));
  protected readonly display = computed(() => {
    const records = this.records().slice(this.start(), this.end());
    const columns = [...new Set(records.flatMap(record => Object.keys(record)))];
    return { columns, rows: records.map(record => columns.map(column => {
      const value = record[column];
      return value == null ? '—' : typeof value === 'object' ? JSON.stringify(value) : String(value);
    })) };
  });
}
