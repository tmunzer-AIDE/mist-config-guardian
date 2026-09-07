import { HttpErrorResponse } from '@angular/common/http';
import { Component, inject, OnInit, signal } from '@angular/core';
import { FormControl, FormGroup, ReactiveFormsModule } from '@angular/forms';
import { finalize } from 'rxjs';

import { ApplicationSettingsService } from './application-settings.service';

@Component({
  selector: 'app-administration-page',
  imports: [ReactiveFormsModule],
  templateUrl: './administration-page.html',
  styleUrl: './administration-page.scss',
})
export class AdministrationPage implements OnInit {
  private readonly settingsApi = inject(ApplicationSettingsService);

  protected readonly loading = signal(true);
  protected readonly saving = signal(false);
  protected readonly error = signal('');
  protected readonly success = signal('');
  protected readonly apiKeySet = signal(false);
  protected readonly apiKeyLastFour = signal<string | null>(null);

  protected readonly form = new FormGroup({
    enabled: new FormControl(false, { nonNullable: true }),
    base_url: new FormControl('', { nonNullable: true }),
    model: new FormControl('', { nonNullable: true }),
    api_key: new FormControl('', { nonNullable: true }),
    clear_api_key: new FormControl(false, { nonNullable: true }),
  });

  ngOnInit(): void {
    this.settingsApi
      .getImpactAi()
      .pipe(finalize(() => this.loading.set(false)))
      .subscribe({
        next: (settings) => {
          this.apiKeySet.set(settings.api_key_set);
          this.apiKeyLastFour.set(settings.api_key_last_four);
          this.form.reset({
            enabled: settings.enabled,
            base_url: settings.base_url,
            model: settings.model,
            api_key: '',
            clear_api_key: false,
          });
        },
        error: (error: HttpErrorResponse) => this.error.set(this.errorMessage(error)),
      });
  }

  protected save(): void {
    if (this.saving()) {
      return;
    }
    const value = this.form.getRawValue();
    const apiKey = value.api_key.trim();
    if (
      value.enabled &&
      (!value.base_url.trim() ||
        !value.model.trim() ||
        (!apiKey && (!this.apiKeySet() || value.clear_api_key)))
    ) {
      this.error.set('Base URL, model, and an API key are required when AI analysis is enabled.');
      return;
    }

    this.error.set('');
    this.success.set('');
    this.saving.set(true);
    this.settingsApi
      .updateImpactAi({
        enabled: value.enabled,
        base_url: value.base_url.trim(),
        model: value.model.trim(),
        api_key: apiKey || null,
        clear_api_key: value.clear_api_key,
      })
      .pipe(finalize(() => this.saving.set(false)))
      .subscribe({
        next: (settings) => {
          this.apiKeySet.set(settings.api_key_set);
          this.apiKeyLastFour.set(settings.api_key_last_four);
          this.form.patchValue({ api_key: '', clear_api_key: false });
          this.success.set('AI impact analysis settings saved.');
        },
        error: (error: HttpErrorResponse) => this.error.set(this.errorMessage(error)),
      });
  }

  private errorMessage(error: HttpErrorResponse): string {
    return typeof error.error?.detail === 'string'
      ? error.error.detail
      : 'Unable to save AI impact analysis settings.';
  }
}
