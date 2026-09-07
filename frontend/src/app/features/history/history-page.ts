import { DatePipe, JsonPipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, computed, inject, OnInit, signal } from '@angular/core';
import { finalize } from 'rxjs';

import { Organization } from '../organizations/organization.model';
import { OrganizationService } from '../organizations/organization.service';
import { ConfigurationObject, ConfigurationVersion } from './history.model';
import { HistoryService } from './history.service';

@Component({
  selector: 'app-history-page',
  imports: [DatePipe, JsonPipe],
  templateUrl: './history-page.html',
  styleUrl: './history-page.scss',
})
export class HistoryPage implements OnInit {
  private readonly organizationsApi = inject(OrganizationService);
  private readonly historyApi = inject(HistoryService);

  protected readonly organizations = signal<Organization[]>([]);
  protected readonly selectedOrganizationId = signal('');
  protected readonly objects = signal<ConfigurationObject[]>([]);
  protected readonly selectedObject = signal<ConfigurationObject | null>(null);
  protected readonly versions = signal<ConfigurationVersion[]>([]);
  protected readonly selectedVersionIndex = signal(0);
  protected readonly includeDeleted = signal(false);
  protected readonly loading = signal(true);
  protected readonly error = signal('');
  protected readonly selectedVersion = computed(
    () => this.versions()[this.selectedVersionIndex()] ?? null,
  );

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
    this.selectedObject.set(null);
    this.versions.set([]);
    this.loadObjects();
  }

  protected toggleDeleted(checked: boolean): void {
    this.includeDeleted.set(checked);
    this.loadObjects();
  }

  protected selectObject(object: ConfigurationObject): void {
    this.selectedObject.set(object);
    this.selectedVersionIndex.set(0);
    this.error.set('');
    this.historyApi.versions(this.selectedOrganizationId(), object.id).subscribe({
      next: (result) => this.versions.set(result.items),
      error: (error: HttpErrorResponse) => this.error.set(this.errorMessage(error)),
    });
  }

  protected older(): void {
    this.selectedVersionIndex.update((index) => Math.min(index + 1, this.versions().length - 1));
  }

  protected newer(): void {
    this.selectedVersionIndex.update((index) => Math.max(index - 1, 0));
  }

  private loadObjects(): void {
    const organizationId = this.selectedOrganizationId();
    if (!organizationId) {
      return;
    }
    this.loading.set(true);
    this.error.set('');
    this.historyApi
      .objects(organizationId, this.includeDeleted())
      .pipe(finalize(() => this.loading.set(false)))
      .subscribe({
        next: (result) => this.objects.set(result.items),
        error: (error: HttpErrorResponse) => this.error.set(this.errorMessage(error)),
      });
  }

  private errorMessage(error: HttpErrorResponse): string {
    return typeof error.error?.detail === 'string'
      ? error.error.detail
      : 'Configuration history could not be loaded.';
  }
}
