import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, inject, OnInit, signal } from '@angular/core';
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { finalize, forkJoin } from 'rxjs';

import {
  MistCloudRegion,
  Organization,
  SnapshotManifest,
  WebhookSecret,
} from './organization.model';
import { OrganizationService } from './organization.service';

@Component({
  selector: 'app-organizations-page',
  imports: [DatePipe, ReactiveFormsModule],
  templateUrl: './organizations-page.html',
  styleUrl: './organizations-page.scss',
})
export class OrganizationsPage implements OnInit {
  private readonly organizationsApi = inject(OrganizationService);

  protected readonly organizations = signal<Organization[]>([]);
  protected readonly loading = signal(true);
  protected readonly saving = signal(false);
  protected readonly error = signal('');
  protected readonly showCreate = signal(false);
  protected readonly snapshotStatus = signal<Record<string, SnapshotManifest | 'queued' | null>>({});
  protected readonly snapshotRunning = signal<Record<string, boolean>>({});
  protected readonly webhookSetup = signal<Record<string, WebhookSecret>>({});
  protected readonly webhookRotating = signal<Record<string, boolean>>({});

  protected readonly createForm = new FormGroup({
    cloud_region: new FormControl<MistCloudRegion>('global_01', {
      nonNullable: true,
      validators: [Validators.required],
    }),
    service_token: new FormControl('', {
      nonNullable: true,
      validators: [Validators.required],
    }),
    reconciliation_cron: new FormControl('0 2 * * *', {
      nonNullable: true,
      validators: [Validators.required],
    }),
    configuration_retention_days: new FormControl(365, {
      nonNullable: true,
      validators: [Validators.required, Validators.min(1)],
    }),
    monitoring_retention_days: new FormControl(90, {
      nonNullable: true,
      validators: [Validators.required, Validators.min(1)],
    }),
  });

  ngOnInit(): void {
    this.load();
  }

  protected create(): void {
    if (this.createForm.invalid || this.saving()) {
      this.createForm.markAllAsTouched();
      return;
    }
    this.saving.set(true);
    this.error.set('');
    this.organizationsApi
      .create(this.createForm.getRawValue())
      .pipe(finalize(() => this.saving.set(false)))
      .subscribe({
        next: (organization) => {
          this.organizations.update((items) =>
            [...items, organization].sort((left, right) => left.name.localeCompare(right.name)),
          );
          this.createForm.reset({
            cloud_region: 'global_01',
            service_token: '',
            reconciliation_cron: '0 2 * * *',
            configuration_retention_days: 365,
            monitoring_retention_days: 90,
          });
          this.showCreate.set(false);
        },
        error: (error: HttpErrorResponse) => this.error.set(this.errorMessage(error)),
      });
  }

  protected verify(organization: Organization): void {
    this.error.set('');
    this.organizationsApi.verify(organization.id).subscribe({
      next: (updated) =>
        this.organizations.update((items) =>
          items.map((item) => (item.id === updated.id ? updated : item)),
        ),
      error: (error: HttpErrorResponse) => this.error.set(this.errorMessage(error)),
    });
  }

  protected triggerSnapshot(organization: Organization): void {
    if (this.snapshotRunning()[organization.id]) {
      return;
    }
    const kind = organization.initial_snapshot_completed_at ? 'manual' : 'initial';
    this.snapshotRunning.update((state) => ({ ...state, [organization.id]: true }));
    this.error.set('');
    this.organizationsApi
      .triggerSnapshot(organization.id, kind)
      .pipe(
        finalize(() =>
          this.snapshotRunning.update((state) => ({ ...state, [organization.id]: false })),
        ),
      )
      .subscribe({
        next: () =>
          this.snapshotStatus.update((state) => ({ ...state, [organization.id]: 'queued' })),
        error: (error: HttpErrorResponse) => this.error.set(this.errorMessage(error)),
      });
  }

  protected snapshotLabel(organization: Organization): string {
    const snapshot = this.snapshotStatus()[organization.id];
    if (snapshot === 'queued') {
      return 'Queued';
    }
    if (snapshot) {
      return `${snapshot.status} · ${snapshot.discovered_objects} objects`;
    }
    return organization.initial_snapshot_completed_at ? 'Complete' : 'Pending';
  }

  protected rotateWebhookSecret(organization: Organization): void {
    if (
      organization.webhook_secret_set &&
      !window.confirm('Rotate this webhook secret? Existing Mist deliveries will fail until updated.')
    ) {
      return;
    }
    this.webhookRotating.update((state) => ({ ...state, [organization.id]: true }));
    this.error.set('');
    this.organizationsApi
      .rotateWebhookSecret(organization.id)
      .pipe(
        finalize(() =>
          this.webhookRotating.update((state) => ({ ...state, [organization.id]: false })),
        ),
      )
      .subscribe({
        next: (setup) => {
          this.webhookSetup.update((state) => ({
            ...state,
            [organization.id]: {
              ...setup,
              endpoint: `${window.location.origin}${setup.endpoint}`,
            },
          }));
          this.organizations.update((items) =>
            items.map((item) =>
              item.id === organization.id
                ? {
                    ...item,
                    webhook_secret_set: true,
                    webhook_secret_last_four: setup.secret.slice(-4),
                  }
                : item,
            ),
          );
        },
        error: (error: HttpErrorResponse) => this.error.set(this.errorMessage(error)),
      });
  }

  private load(): void {
    this.loading.set(true);
    this.organizationsApi
      .list()
      .pipe(finalize(() => this.loading.set(false)))
      .subscribe({
        next: (result) => {
          this.organizations.set(result.items);
          this.loadSnapshotStatus(result.items);
        },
        error: (error: HttpErrorResponse) => this.error.set(this.errorMessage(error)),
      });
  }

  private loadSnapshotStatus(organizations: Organization[]): void {
    if (organizations.length === 0) {
      return;
    }
    forkJoin(
      Object.fromEntries(
        organizations.map((organization) => [
          organization.id,
          this.organizationsApi.snapshots(organization.id),
        ]),
      ),
    ).subscribe({
      next: (results) =>
        this.snapshotStatus.set(
          Object.fromEntries(
            Object.entries(results).map(([id, result]) => [id, result.items[0] ?? null]),
          ),
        ),
      error: (error: HttpErrorResponse) => this.error.set(this.errorMessage(error)),
    });
  }

  private errorMessage(error: HttpErrorResponse): string {
    return typeof error.error?.detail === 'string' ? error.error.detail : 'The request could not be completed.';
  }
}
