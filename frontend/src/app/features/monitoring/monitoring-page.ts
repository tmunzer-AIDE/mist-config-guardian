import { DatePipe, DecimalPipe, JsonPipe, KeyValuePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, inject, OnInit, signal } from '@angular/core';
import { finalize } from 'rxjs';

import { Organization } from '../organizations/organization.model';
import { OrganizationService } from '../organizations/organization.service';
import { MonitoringSession } from './monitoring.model';
import { MonitoringService } from './monitoring.service';

@Component({
  selector: 'app-monitoring-page',
  imports: [DatePipe, DecimalPipe, JsonPipe, KeyValuePipe],
  templateUrl: './monitoring-page.html',
  styleUrl: './monitoring-page.scss',
})
export class MonitoringPage implements OnInit {
  private readonly organizationsApi = inject(OrganizationService);
  private readonly monitoringApi = inject(MonitoringService);

  protected readonly organizations = signal<Organization[]>([]);
  protected readonly selectedOrganizationId = signal('');
  protected readonly sessions = signal<MonitoringSession[]>([]);
  protected readonly selected = signal<MonitoringSession | null>(null);
  protected readonly statusFilter = signal('');
  protected readonly loading = signal(true);
  protected readonly error = signal('');

  ngOnInit(): void {
    this.organizationsApi
      .list()
      .pipe(finalize(() => this.loading.set(false)))
      .subscribe({
        next: (result) => {
          this.organizations.set(result.items);
          if (result.items[0]) {
            this.selectOrganization(result.items[0].id);
          }
        },
        error: (error: HttpErrorResponse) => this.error.set(this.errorMessage(error)),
      });
  }

  protected selectOrganization(organizationId: string): void {
    this.selectedOrganizationId.set(organizationId);
    this.selected.set(null);
    this.load();
  }

  protected filter(status: string): void {
    this.statusFilter.set(status);
    this.selected.set(null);
    this.load();
  }

  protected refresh(): void {
    this.load(this.selected()?.id);
  }

  protected choose(session: MonitoringSession): void {
    this.monitoringApi.get(this.selectedOrganizationId(), session.id).subscribe({
      next: (result) => this.selected.set(result),
      error: (error: HttpErrorResponse) => this.error.set(this.errorMessage(error)),
    });
  }

  protected latest(session: MonitoringSession) {
    return session.observations.at(-1) ?? null;
  }

  protected delta(session: MonitoringSession, metric: string): number | null {
    const baseline = session.baseline?.values[metric];
    const current = this.latest(session)?.values[metric];
    return baseline === undefined || current === undefined ? null : current - baseline;
  }

  protected currentValue(session: MonitoringSession, metric: string): number | null {
    return this.latest(session)?.values[metric] ?? null;
  }

  private load(reselectId?: string): void {
    const organizationId = this.selectedOrganizationId();
    if (!organizationId) {
      return;
    }
    this.loading.set(true);
    this.error.set('');
    this.monitoringApi
      .list(organizationId, this.statusFilter() || undefined)
      .pipe(finalize(() => this.loading.set(false)))
      .subscribe({
        next: (result) => {
          this.sessions.set(result.items);
          const selected = result.items.find((item) => item.id === reselectId);
          this.selected.set(selected ?? null);
        },
        error: (error: HttpErrorResponse) => this.error.set(this.errorMessage(error)),
      });
  }

  private errorMessage(error: HttpErrorResponse): string {
    return typeof error.error?.detail === 'string'
      ? error.error.detail
      : 'Impact monitoring data could not be loaded.';
  }
}
