import { TestBed } from '@angular/core/testing';

import { GuardianResult, GuardianSummary } from '../core/guardian.model';
import { GuardianBadge } from './guardian-badge';

function result(overrides: Partial<GuardianResult> = {}): GuardianResult {
  return {
    run_id: 'run-1',
    run_kind: 'final',
    evaluated_at: '2026-09-07T09:22:00Z',
    peak: 'none',
    current: 'none',
    recovery: 'none',
    confidence: 'medium',
    coverage: 'complete',
    sources: ['monitoring', 'deployment'],
    impacted_devices: [],
    impacted_device_count: 0,
    summary: 'No monitored device lost service after the change.',
    ...overrides,
  };
}

function summary(overrides: Partial<GuardianSummary> = {}): GuardianSummary {
  return { availability: 'projected', status: 'done', status_reason: null, result: result(), ...overrides };
}

function render(value: GuardianSummary | null | undefined, compact = false, scope = ''): HTMLElement {
  const fixture = TestBed.createComponent(GuardianBadge);
  if (value !== undefined) {
    fixture.componentRef.setInput('summary', value);
  }
  fixture.componentRef.setInput('compact', compact);
  fixture.componentRef.setInput('scope', scope);
  fixture.detectChanges();
  return fixture.nativeElement as HTMLElement;
}

describe('GuardianBadge', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({ imports: [GuardianBadge] }).compileComponents();
  });

  it('says an investigation is still running rather than showing a result it does not have', () => {
    const element = render(summary({ status: 'waiting', status_reason: 'Early window not reached', result: null }));

    expect(element.textContent).toContain('Guardian · Investigating');
    expect(element.textContent).toContain('No result has been published yet');
    expect(element.textContent).toContain('Early window not reached');
    expect(element.textContent).not.toContain('Peak:');
  });

  it('names the scope its bands are measured over when the page gives one', () => {
    const impacted = summary({ result: result({ peak: 'warning', recovery: 'recovered' }) });
    const scoped = render(impacted, false, 'For this audit, across all sites');
    const unscoped = render(impacted);

    expect(scoped.textContent).toContain('For this audit, across all sites');
    expect(unscoped.textContent).not.toContain('across all sites');
  });

  it('distinguishes no investigation from a clean one', () => {
    const element = render(null);

    expect(element.textContent).toContain('No investigation recorded');
    expect(element.textContent).toContain('No Guardian investigation was recorded');
    expect(element.textContent).not.toContain('No impact observed');
  });

  it('renders nothing at all when the page asked for no Guardian answer', () => {
    expect(render(undefined).textContent?.trim()).toBe('');
  });

  it('reports a result it could not read as unknown, never as clean', () => {
    const element = render({ availability: 'unavailable', status: null, status_reason: null, result: null });

    expect(element.textContent).toContain('could not be read');
    expect(element.textContent).toContain('not a clean result');
    expect(element.textContent).not.toContain('No impact observed');
    expect(element.textContent).not.toContain('Peak:');
  });

  it('shows a clean result with its peak, current, confidence and coverage', () => {
    const element = render(summary());

    expect(element.textContent).toContain('Guardian · No impact observed');
    expect(element.textContent).toContain('Peak: No impact observed · Current: No impact observed');
    expect(element.textContent).toContain('Confidence: medium · Deterministic coverage: complete');
    expect(element.textContent).toContain('No monitored device lost service');
    expect(element.textContent).toContain('Sources: Monitoring, Deployment');
  });

  it('calls an info peak not established rather than no impact', () => {
    const element = render(summary({ result: result({ peak: 'info', current: 'info', coverage: 'partial', confidence: 'low' }) }));

    expect(element.textContent).toContain('Impact not established');
    expect(element.textContent).toContain('Peak: Impact not established · Current: Impact not established');
    expect(element.textContent).not.toContain('Peak: info');
  });

  it('words both bands, so an unestablished verdict never shows a bare band', () => {
    // The bare enum beside a worded headline reads as its opposite: "Current: none"
    // under an unestablished peak looks like a current state known to be clean.
    const element = render(
      summary({ result: result({ peak: 'info', current: 'none', recovery: 'none', coverage: 'complete', confidence: 'low' }) }),
    );

    expect(element.textContent).toContain('Peak: Impact not established · Current: No impact observed');
    expect(element.textContent).not.toContain('Current: none');
  });

  it('shows a recovered warning as recovered without dropping the peak', () => {
    const element = render(
      summary({ result: result({ peak: 'warning', current: 'none', recovery: 'recovered', coverage: 'partial', confidence: 'low' }) }),
    );

    expect(element.textContent).toContain('Possible disruption');
    expect(element.textContent).toContain('Peak: Possible disruption · Current: No impact observed');
    expect(element.textContent).not.toContain('Peak: warning');
    expect(element.textContent).toContain('Recovered');
  });

  it('labels an early result published by a finished investigation as the last word it will get', () => {
    const element = render(
      summary({
        status: 'done',
        status_reason: 'Final attempts exhausted',
        result: result({ run_kind: 'early', peak: 'warning', current: 'warning', recovery: 'unrecovered', coverage: 'partial', confidence: 'low' }),
      }),
    );

    expect(element.textContent).toContain('Early result');
    expect(element.textContent).toContain('ended without publishing a final result');
    expect(element.textContent).toContain('Final attempts exhausted');
    expect(element.textContent).toContain('Not recovered');
  });

  it('labels an early result of a running investigation as one that may be superseded', () => {
    const element = render(summary({ status: 'waiting', result: result({ run_kind: 'early' }) }));

    expect(element.textContent).toContain('Early result');
    expect(element.textContent).toContain('may publish a final result');
  });

  it('keeps the compact form to the verdict and renders provider text as text', () => {
    const element = render(summary({ result: result({ summary: '<img src=x onerror=alert(1)> device' }) }), true);

    expect(element.querySelector('img')).toBeNull();
    expect(element.textContent).not.toContain('device');
    expect(element.textContent).toContain('Guardian · No impact observed');
  });

  it('renders untrusted summary text as text when it is shown in full', () => {
    const element = render(summary({ result: result({ summary: '<img src=x onerror=alert(1)>' }) }));

    expect(element.querySelector('img')).toBeNull();
    expect(element.textContent).toContain('<img src=x onerror=alert(1)>');
  });
});
