import { TestBed } from '@angular/core/testing';
import { McpCheckpoint, McpInvestigationComponent } from './mcp-investigation';

const checkpoint: McpCheckpoint = {
  source: 'mcp_agent', state: 'complete', reason: '',
  conclusion: { summary: 'Possible interruption', impact: 'warning', confidence: 'low', coverage: 'partial',
    findings: [{ statement: 'Port down on changed switch', evidence: ['e1'], limitations: ['Timing alone is not causation'] }], gaps: [] },
  evidence: [{ id: 'e1', tool: 'search_mist_data', state: 'partial', arguments: { search_type: 'device_events' },
    data: { name: '<img src=x onerror=alert(1)>', count: 0 }, error: null, captured_at: '2026-09-13T10:00:00Z' }],
};

describe('MCP investigation', () => {
  it('renders findings, citations, bounded requests and responses as text', () => {
    TestBed.configureTestingModule({ imports: [McpInvestigationComponent] });
    const fixture = TestBed.createComponent(McpInvestigationComponent);
    fixture.componentRef.setInput('checkpoint', checkpoint);
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('Port down on changed switch');
    expect(fixture.nativeElement.textContent).toContain('Evidence: e1');
    expect(fixture.nativeElement.textContent).toContain('Timing alone is not causation');
    expect(fixture.nativeElement.textContent).toContain('"count": 0');
    expect(fixture.nativeElement.querySelector('img')).toBeNull();
  });
  it('shows an explicit provider gap without fabricating a conclusion', () => {
    TestBed.configureTestingModule({ imports: [McpInvestigationComponent] });
    const fixture = TestBed.createComponent(McpInvestigationComponent);
    fixture.componentRef.setInput('checkpoint', { ...checkpoint, state: 'unavailable', conclusion: null,
      evidence: [], reason: 'MCP authentication failed' });
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('MCP authentication failed');
    expect(fixture.nativeElement.textContent).not.toContain('Port down on changed switch');
  });
});
