import { ChangeDetectionStrategy, Component } from '@angular/core';

@Component({
  selector: 'app-changes-page',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<div class="page"><h1 class="cg-page-title">Changes</h1></div>`,
  styles: `.page { padding: 20px; }`,
})
export class ChangesPage {}
