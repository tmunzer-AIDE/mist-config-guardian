import { ChangeDetectionStrategy, Component, input } from '@angular/core';
import { EvidenceDataset, ImpactReport } from '../core/impact-report.model';
import { formatInstant } from '../core/format';

@Component({
  selector: 'app-impact-report',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (report(); as report) {
      <section aria-label="Structured impact report">
        <h3>Impact report · revision {{ report.revision }}</h3>
        <p class="ratings"><strong>Peak impact: {{ band(report.peak_impact) }}</strong>
          · Confidence: {{ report.peak_confidence }} · source revision {{ report.peak_revision }}</p>
        <p><strong>Current impact: {{ band(report.current_impact) }}</strong> · Confidence: {{ report.confidence }}
          · Coverage: {{ report.coverage }} · Attribution: {{ report.attribution }}</p>
        <p>Evidence through {{ at(report.evidence_as_of) }}. Confidence is an evidence band, not a probability.</p>
        @if (!report.history_complete) { <p role="status">Earlier report history is incomplete; the recorded peak may be incomplete.</p> }
        <details><summary>Report coverage</summary>
          <dl>@for (key of sections; track key) {
            <dt>{{ labels[key] }} · {{ report.sections[key].state }}</dt>
            <dd>{{ report.sections[key].explanation }}</dd>
          }</dl>
        </details>
        <h4>Impacted services and associated devices</h4>
        <p>Observed associations only. These records do not establish that an entire device failed.</p>
        @if (report.impacted_devices.length) {
          <div class="scroll"><table>
            <thead><tr><th>Device</th><th>Service / role</th><th>Peak / current</th><th>Confidence</th></tr></thead>
            <tbody>@for (device of report.impacted_devices; track $index) {
              <tr><td>{{ device.device_mac }} {{ device.port_id }}</td>
                <td>{{ device.service }} · {{ device.role === 'serving_affected_clients' ? 'Served affected clients' : 'Affected switch port' }}</td>
                <td>{{ band(device.impact) }} / {{ band(device.current_impact) }}</td><td>{{ device.confidence }} · attribution provisional</td></tr>
            }</tbody>
          </table></div>
        } @else { <p>No device service association was established. This is not a clean bill of health.</p> }
        @if (report.omitted_device_impacts) { <p>{{ report.omitted_device_impacts }} additional service associations omitted.</p> }
        <h4>Evidence views</h4>
        @for (dataset of report.datasets; track dataset.id) {
          <details><summary>{{ dataset.title }} · {{ dataset.state }}</summary>
            <p>{{ dataset.explanation }}</p>
            <p>{{ at(dataset.window.start) }}–{{ at(dataset.window.end) }} · collected {{ at(dataset.captured_at) }}</p>
            @if (dataset.kind === 'bar' || dataset.kind === 'histogram') {
              <div class="bars" role="img" [attr.aria-label]="dataset.title + '. Values are listed in the table below.'">
                @for (row of dataset.rows; track $index) {
                  <div class="bar-row"><span>{{ row[0] }} {{ dataset.kind === 'histogram' ? row[1] : '' }}</span>
                    <span class="track"><span class="fill" [style.width.%]="width(dataset, row)" ></span></span>
                    <span>{{ row[row.length - 1] }}</span></div>
                }
              </div>
            }
            <div class="scroll"><table>
              <caption>{{ dataset.kind === 'timeline' ? 'Recorded event timeline' : 'Source values' }}</caption>
              <thead><tr>@for (column of dataset.columns; track $index) { <th>{{ column }}</th> }</tr></thead>
              <tbody>@for (row of dataset.rows; track $index) {
                <tr>@for (cell of row; track $index) { <td>{{ cell ?? 'Unknown' }}</td> }</tr>
              }</tbody>
            </table></div>
            @if (!dataset.rows.length) { <p>No rows returned. Check completeness before interpreting absence.</p> }
            @if (dataset.omitted_rows) { <p>{{ dataset.omitted_rows }} rows omitted from this view.</p> }
          </details>
        }
        <details><summary>Gaps and next checks</summary><ul>
          @for (gap of report.gaps; track $index) { <li>{{ gap }}</li> }
        </ul></details>
      </section>
    }
  `,
  styles: `
    :host { display:block; } section { border: 1px solid var(--border); padding:1rem; border-radius:.5rem; }
    h3,h4 { margin:.6rem 0; } p,li { line-height:1.5; } details { margin:.7rem 0; }
    summary { cursor:pointer; } .scroll { overflow-x:auto; } table { width:100%; border-collapse:collapse; }
    td,th { text-align:left; padding:.5rem; border-bottom:1px solid var(--border); } caption { text-align:left; }
    .bars { max-height:20rem; overflow:auto; margin:1rem 0; } .bar-row { display:grid; grid-template-columns:minmax(6rem, 1fr) 2fr 3rem; gap:.5rem; margin:.3rem 0; font-size:.8rem; }
    .track { display:block; background:var(--border); align-self:center; height:.7rem; } .fill { display:block; height:100%; background:var(--accent, #3982ce); }
    dt { font-weight:600; margin-top:.5rem; } dd { margin:.25rem 0; }
  `,
})
export class ImpactReportComponent {
  readonly report = input<ImpactReport | null>(null);
  protected readonly at = (value: string) => formatInstant(new Date(value));
  protected readonly sections = ['summary', 'change', 'scope', 'findings', 'evidence', 'timeline', 'context', 'gaps_and_next_checks'] as const;
  protected readonly labels = { summary: 'Summary', change: 'Change', scope: 'Scope', findings: 'Findings', evidence: 'Evidence', timeline: 'Timeline', context: 'Context', gaps_and_next_checks: 'Gaps and next checks' };
  protected band(value: string): string { return value === 'info' ? 'Unknown' : value === 'none' ? 'No observed impact' : value; }
  protected width(dataset: EvidenceDataset, row: (string | number | null)[]): number {
    const value = row[row.length - 1];
    const max = Math.max(0, ...dataset.rows.map(r => typeof r[r.length - 1] === 'number' ? r[r.length - 1] as number : 0));
    return typeof value === 'number' && Number.isFinite(value) && max > 0 ? Math.max(0, Math.min(100, value / max * 100)) : 0;
  }
}
