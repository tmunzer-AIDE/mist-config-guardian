import { ChangeDetectionStrategy, Component, input } from '@angular/core';

export interface PortEvent { event_type: string; occurred_at: string; }

@Component({
  selector: 'app-port-events',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (events()?.length) {
      <table><caption>Exact-port event history</caption>
        <thead><tr><th>Occurred</th><th>Event</th></tr></thead>
        <tbody>@for (event of events(); track $index) {
          <tr><td>{{ event.occurred_at }}</td><td>{{ event.event_type }}</td></tr>
        }</tbody>
      </table>
      <p>PoE enabled/disabled events alone do not establish power delivery or AP failure.</p>
    }
    @if (omitted()) { <p>{{ omitted() }} events omitted from this agent view; retained evidence is available in collection checks.</p> }
  `,
  styles: `:host { display:block; overflow-wrap:anywhere; } table { width:100%; } th,td { text-align:left; padding:.2rem; }`,
})
export class PortEventsComponent {
  readonly events = input<PortEvent[] | null>();
  readonly omitted = input<number>(0);
}
