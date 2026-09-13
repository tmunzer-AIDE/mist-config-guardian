import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { AgentCheckpoint, AgentInvestigationComponent, ModelActivity } from './agent-investigation';

const checkpoint: AgentCheckpoint = {
  source: 'model_proposal', state: 'complete', reason: '',
  proposal: { summary: 'A possible disconnect needs review.', hypotheses: [{
    target_handle: 'target-1', statement: '<img src=x onerror=alert(1)>',
    supporting_checks: ['check-1'], counterevidence_checks: [], limitations: ['Roaming remains possible.'],
  }], open_questions: ['Failed joins are not available.'] },
  memory: { source_revision: 2, proposal: { summary: 'Previous hypothesis, not fresh evidence.', hypotheses: [], open_questions: [] } },
  observations: [{ ref: 'check-1', target_handle: 'target-1', state: 'partial', sampled_clients: 0,
    observed_disconnects: 0, gap: 'Incomplete history', window: { start: '2026-09-12T10:00:00Z', end: '2026-09-12T10:10:00Z' } }],
};
const activity: ModelActivity = {
  source: 'live_investigation_root', calls_used: 2, calls_limit: 21, input_bytes_reserved: 1000, input_bytes_limit: 504000,
  records: [{ id: 'request-2', candidate_revision: 3, model: 'test-model', state: 'reserved',
    reserved_at: '2026-09-12T10:10:00Z', finished_at: null, request_tokens: null, response_tokens: null,
    input_hash: 'hash' }],
};

describe('Agent investigation', () => {
  it('labels proposals, limitations and historical memory without promoting attribution', async () => {
    await TestBed.configureTestingModule({ imports: [AgentInvestigationComponent], providers: [provideHttpClient(), provideHttpClientTesting()] }).compileComponents();
    const fixture = TestBed.createComponent(AgentInvestigationComponent);
    fixture.componentRef.setInput('checkpoint', checkpoint);
    fixture.detectChanges();
    const text = fixture.nativeElement.textContent;
    expect(text).toContain('hypotheses for review');
    expect(text).toContain('do not prove attribution');
    expect(text).toContain('Roaming remains possible');
    expect(text).toContain('source revision 2');
    expect(text).toContain('not fresh evidence');
    expect(text).toContain('Incomplete history');
    expect(fixture.nativeElement.querySelector('img')).toBeNull();
  });

  it('shows live unfinished model requests even without a published proposal', async () => {
    await TestBed.configureTestingModule({ imports: [AgentInvestigationComponent], providers: [provideHttpClient(), provideHttpClientTesting()] }).compileComponents();
    const fixture = TestBed.createComponent(AgentInvestigationComponent);
    fixture.componentRef.setInput('activity', activity);
    fixture.detectChanges();
    const text = fixture.nativeElement.textContent;
    expect(text).toContain('Outcome unknown');
    expect(text).toContain('input Unknown');
    expect(text).toContain('Load request context and action');
    expect(text).toContain('outside this published revision');
    expect(text).not.toContain('Proposal ready');
    expect(fixture.nativeElement.querySelector('img')).toBeNull();
  });
  it('distinguishes classified rejections from historical missing diagnostics', async () => {
    await TestBed.configureTestingModule({ imports: [AgentInvestigationComponent], providers: [provideHttpClient(), provideHttpClientTesting()] }).compileComponents();
    const fixture = TestBed.createComponent(AgentInvestigationComponent);
    fixture.componentRef.setInput('activity', { ...activity, records: [
      { ...activity.records[0], state: 'invalid_response', response_error: 'empty_collection' },
      { ...activity.records[0], id: 'old-request', state: 'invalid_response' },
    ] });
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('Validation failure: empty_collection');
    expect(fixture.nativeElement.textContent).toContain('Specific validation reason was not recorded');
  });

});
