import { Component, input } from '@angular/core';

@Component({
  selector: 'app-placeholder-page',
  template: `
    <section class="placeholder">
      <p>{{ description() }}</p>
      <div class="panel">
        <strong>{{ title() }}</strong>
        <span>This workspace is ready for the first feature slice.</span>
      </div>
    </section>
  `,
  styles: `
    .placeholder {
      color: #52627a;
      margin-top: 3rem;
      max-width: 760px;
    }

    .panel {
      background: #fff;
      border: 1px solid #dfe5ee;
      border-radius: 0.85rem;
      box-shadow: 0 8px 30px rgb(24 44 78 / 6%);
      display: grid;
      gap: 0.5rem;
      margin-top: 1.25rem;
      padding: 1.5rem;
    }

    .panel strong {
      color: #1e2b40;
      font-size: 1.1rem;
    }
  `,
})
export class PlaceholderPage {
  readonly title = input.required<string>();
  readonly description = input.required<string>();
}
