import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';

import { API_ROOT } from '../../core/api';
import { AiSettingsService } from '../settings/ai-settings.service';
import { AiAssistService } from './ai-assist.service';

const STORED = {
  enabled: true,
  base_url: 'https://llm.example/v1',
  model: 'm',
  api_key_set: true,
  api_key_last_four: '7Qd3',
  max_response_tokens: 1500,
  automatic_summaries: false,
  last_test_at: null,
  last_test_ok: null,
  last_test_detail: null,
};

describe('AiAssistService availability', () => {
  let http: HttpTestingController;
  let ai: AiAssistService;

  beforeEach(() => {
    TestBed.configureTestingModule({ providers: [provideHttpClient(), provideHttpClientTesting()] });
    http = TestBed.inject(HttpTestingController);
    ai = TestBed.inject(AiAssistService);
  });

  afterEach(() => http.verify());

  /** Let a read the service started on its own land. */
  async function settle(): Promise<void> {
    for (let turn = 0; turn < 5; turn += 1) {
      await Promise.resolve();
    }
  }

  async function resolve(status: { enabled: boolean; automatic_summaries: boolean }): Promise<void> {
    const loading = ai.loadStatus();
    http.expectOne(`${API_ROOT}/ai/status`).flush(status);
    await loading;
  }

  it('learns availability from the status every role can read', async () => {
    const loading = ai.loadStatus();
    http.expectNone(`${API_ROOT}/ai/settings`);
    http.expectOne(`${API_ROOT}/ai/status`).flush({ enabled: true, automatic_summaries: true });
    await loading;

    expect(ai.availability()).toBe('enabled');
    expect(ai.automatic()).toBe(true);
  });

  it('reads the status again once an administrator saves AI settings', async () => {
    await resolve({ enabled: false, automatic_summaries: false });
    expect(ai.availability()).toBe('disabled');

    const saving = TestBed.inject(AiSettingsService).save({
      enabled: true,
      base_url: STORED.base_url,
      model: STORED.model,
      max_response_tokens: 1500,
      automatic_summaries: false,
    });
    http.expectOne((request) => request.method === 'PUT' && request.url === `${API_ROOT}/ai/settings`).flush(STORED);
    await saving;
    http.expectOne(`${API_ROOT}/ai/status`).flush({ enabled: true, automatic_summaries: false });
    await settle();

    expect(ai.availability()).toBe('enabled');
  });

  it('forgets a refusal once a later configuration is enabled and answers', async () => {
    await resolve({ enabled: true, automatic_summaries: false });
    const refused = ai.summarise({ organization_id: 'org-1', from_version_id: 'v1', to_version_id: 'v2' });
    http
      .expectOne(`${API_ROOT}/ai/diff-summary`)
      .flush({ detail: 'AI assist is not configured' }, { status: 409, statusText: 'Conflict' });
    await refused;
    expect(ai.availability()).toBe('disabled');

    // The administrator fixes the provider and tests it successfully.
    const testing = TestBed.inject(AiSettingsService).test({ base_url: STORED.base_url, model: STORED.model });
    http
      .expectOne(`${API_ROOT}/ai/settings/test`)
      .flush({ ok: true, detail: 'Connected.', checked_at: '2026-10-04T12:00:00Z' });
    await testing;
    http.expectOne(`${API_ROOT}/ai/status`).flush({ enabled: true, automatic_summaries: false });
    await settle();

    expect(ai.refused()).toBe(false);
    expect(ai.availability()).toBe('enabled');
  });

  it('keeps the newest status when two reads answer out of order', async () => {
    await resolve({ enabled: false, automatic_summaries: false });
    const older = ai.loadStatus(true);
    const newer = ai.loadStatus(true);
    const [first, second] = http.match(`${API_ROOT}/ai/status`);
    second.flush({ enabled: true, automatic_summaries: false });
    await newer;
    first.flush({ enabled: false, automatic_summaries: false });
    await older;

    expect(ai.availability()).toBe('enabled');
  });
});
