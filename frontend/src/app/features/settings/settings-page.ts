import { ChangeDetectionStrategy, Component } from '@angular/core';

@Component({
  selector: 'app-settings-page',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<div class="page"><h1 class="cg-page-title">Settings</h1></div>`,
  styles: `.page { padding: 20px; }`,
})
export class SettingsPage {}
