import { HttpClient } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';

import { ImpactAiSettings, ImpactAiSettingsUpdate } from './application-settings.model';

@Injectable({ providedIn: 'root' })
export class ApplicationSettingsService {
  private readonly http = inject(HttpClient);

  getImpactAi() {
    return this.http.get<ImpactAiSettings>('/api/v1/settings/impact-ai');
  }

  updateImpactAi(request: ImpactAiSettingsUpdate) {
    return this.http.put<ImpactAiSettings>('/api/v1/settings/impact-ai', request);
  }
}
