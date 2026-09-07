import { HttpClient } from '@angular/common/http';
import { computed, inject, Injectable, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';

import { API_ROOT } from './api';

export type ComponentStatus = 'ok' | 'degraded' | 'failed';

export interface HealthComponent {
  key: string;
  label: string;
  status: ComponentStatus;
  detail: string;
  latency_ms: number | null;
}

export interface SystemHealth {
  status: ComponentStatus;
  checked_at: string;
  components: HealthComponent[];
}

interface LivenessResponse {
  status: 'ok';
  name: string;
  version: string;
}

/** Backend version and aggregate operational health shown in the shell and settings. */
@Injectable({ providedIn: 'root' })
export class SystemHealthService {
  private readonly http = inject(HttpClient);

  readonly version = signal('');
  readonly health = signal<SystemHealth | null>(null);

  /** Null until health has been checked; false when any component is not ok. */
  readonly healthy = computed<boolean | null>(() => {
    const current = this.health();
    return current === null ? null : current.status === 'ok';
  });

  async loadVersion(): Promise<void> {
    try {
      const response = await firstValueFrom(this.http.get<LivenessResponse>(`${API_ROOT}/health`));
      this.version.set(response.version);
    } catch {
      this.version.set('');
    }
  }

  async load(): Promise<SystemHealth | null> {
    try {
      const response = await firstValueFrom(this.http.get<SystemHealth>(`${API_ROOT}/system/health`));
      this.health.set(response);
      return response;
    } catch {
      this.health.set(null);
      return null;
    }
  }
}
