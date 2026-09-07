import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, inject, OnInit, signal } from '@angular/core';
import { FormControl, ReactiveFormsModule } from '@angular/forms';
import { finalize } from 'rxjs';

import { ConfigurationObject, ConfigurationVersion } from '../history/history.model';
import { HistoryService } from '../history/history.service';
import { Organization } from '../organizations/organization.model';
import { OrganizationService } from '../organizations/organization.service';
import { RestoreMode, RestoreOperation } from './restore.model';
import { RestoreService } from './restore.service';

interface RestoreSelection {
  object: ConfigurationObject;
  version: ConfigurationVersion;
}

@Component({
  selector: 'app-restore-page',
  imports: [DatePipe, ReactiveFormsModule],
  templateUrl: './restore-page.html',
  styleUrl: './restore-page.scss',
})
export class RestorePage implements OnInit {
  private readonly organizationsApi = inject(OrganizationService);
  private readonly historyApi = inject(HistoryService);
  private readonly restoresApi = inject(RestoreService);

  protected readonly organizations = signal<Organization[]>([]);
  protected readonly organizationId = signal('');
  protected readonly objects = signal<ConfigurationObject[]>([]);
  protected readonly versions = signal<ConfigurationVersion[]>([]);
  protected readonly objectId = signal('');
  protected readonly versionId = signal('');
  protected readonly selections = signal<RestoreSelection[]>([]);
  protected readonly mode = signal<RestoreMode>('non_destructive');
  protected readonly includeDependencies = signal(true);
  protected readonly plan = signal<RestoreOperation | null>(null);
  protected readonly busy = signal(false);
  protected readonly error = signal('');
  protected readonly administratorToken = new FormControl('', { nonNullable: true });

  ngOnInit(): void {
    this.organizationsApi.list().subscribe({
      next: (result) => {
        this.organizations.set(result.items);
        if (result.items[0]) {
          this.selectOrganization(result.items[0].id);
        }
      },
      error: (error: HttpErrorResponse) => this.error.set(this.errorMessage(error)),
    });
  }

  protected selectOrganization(id: string): void {
    this.organizationId.set(id);
    this.objects.set([]);
    this.versions.set([]);
    this.selections.set([]);
    this.plan.set(null);
    this.historyApi.objects(id, true).subscribe({
      next: (result) => this.objects.set(result.items),
      error: (error: HttpErrorResponse) => this.error.set(this.errorMessage(error)),
    });
  }

  protected selectObject(id: string): void {
    this.objectId.set(id);
    this.versionId.set('');
    this.versions.set([]);
    if (!id) {
      return;
    }
    this.historyApi.versions(this.organizationId(), id).subscribe({
      next: (result) => this.versions.set(result.items),
      error: (error: HttpErrorResponse) => this.error.set(this.errorMessage(error)),
    });
  }

  protected addSelection(): void {
    const object = this.objects().find((item) => item.id === this.objectId());
    const version = this.versions().find((item) => item.id === this.versionId());
    if (!object || !version) {
      return;
    }
    this.selections.update((items) => [
      ...items.filter((item) => item.object.id !== object.id),
      { object, version },
    ]);
    this.plan.set(null);
  }

  protected removeSelection(objectId: string): void {
    this.selections.update((items) => items.filter((item) => item.object.id !== objectId));
    this.plan.set(null);
  }

  protected createPlan(): void {
    if (this.selections().length === 0 || this.busy()) {
      return;
    }
    this.busy.set(true);
    this.error.set('');
    this.restoresApi
      .createPlan(
        this.organizationId(),
        this.selections().map((item) => item.version.id),
        this.mode(),
        this.includeDependencies(),
      )
      .pipe(finalize(() => this.busy.set(false)))
      .subscribe({
        next: (plan) => this.plan.set(plan),
        error: (error: HttpErrorResponse) => this.error.set(this.errorMessage(error)),
      });
  }

  protected execute(): void {
    const plan = this.plan();
    const token = this.administratorToken.value;
    if (!plan || !token || this.busy()) {
      return;
    }
    this.busy.set(true);
    this.error.set('');
    this.restoresApi
      .execute(this.organizationId(), plan.id, token)
      .pipe(finalize(() => this.busy.set(false)))
      .subscribe({
        next: (operation) => {
          this.plan.set(operation);
          this.administratorToken.reset();
        },
        error: (error: HttpErrorResponse) => this.error.set(this.errorMessage(error)),
      });
  }

  private errorMessage(error: HttpErrorResponse): string {
    return typeof error.error?.detail === 'string'
      ? error.error.detail
      : 'The restore request could not be completed.';
  }
}
