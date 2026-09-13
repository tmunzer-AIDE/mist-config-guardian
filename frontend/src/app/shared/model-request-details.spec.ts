import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { ModelRequestDetailsComponent } from './model-request-details';

const payload = { request_id: 'request-1', input_state: 'available',
  input_json: '{"context":"<img src=x onerror=alert(1)>"}', action_state: 'not_recorded', action: null };

describe('Model request details', () => {
  beforeEach(() => TestBed.configureTestingModule({ imports: [ModelRequestDetailsComponent],
    providers: [provideHttpClient(), provideHttpClientTesting()] }));
  afterEach(() => TestBed.inject(HttpTestingController).verify());

  function setup() {
    const fixture = TestBed.createComponent(ModelRequestDetailsComponent);
    fixture.componentRef.setInput('organizationId', 'org-1');
    fixture.componentRef.setInput('groupId', 'group-1');
    fixture.componentRef.setInput('requestId', 'request-1');
    fixture.detectChanges();
    return fixture;
  }

  it('loads only the selected request after a click and escapes its payload', async () => {
    const fixture = setup();
    const http = TestBed.inject(HttpTestingController);
    http.expectNone(() => true);
    fixture.nativeElement.querySelector('button').click();
    http.expectOne(req => req.url.endsWith('/change-groups/group-1/investigation/model-requests/request-1')).flush(payload);
    await fixture.whenStable();
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain(payload.input_json);
    expect(fixture.nativeElement.querySelector('img')).toBeNull();
  });

  it('discards an outstanding response when the organization changes', async () => {
    const fixture = setup();
    fixture.nativeElement.querySelector('button').click();
    const request = TestBed.inject(HttpTestingController).expectOne(() => true);
    fixture.componentRef.setInput('organizationId', 'org-2');
    fixture.detectChanges();
    request.flush(payload);
    await fixture.whenStable();
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).not.toContain(payload.input_json);
  });

  it('labels unavailable and legacy data without treating either as verified current artifacts', async () => {
    const fixture = setup();
    fixture.nativeElement.querySelector('button').click();
    TestBed.inject(HttpTestingController).expectOne(() => true).flush({ ...payload, input_state: 'legacy' });
    await fixture.whenStable(); fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('Legacy embedded payload');
    fixture.nativeElement.querySelector('button').click();
    TestBed.inject(HttpTestingController).expectOne(() => true).flush({ ...payload, input_state: 'unavailable', input_json: null });
    await fixture.whenStable(); fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('unavailable or could not be verified');
    expect(fixture.nativeElement.textContent).not.toContain(payload.input_json);
  });

  it('rejects a response naming another request', async () => {
    const fixture = setup();
    fixture.nativeElement.querySelector('button').click();
    TestBed.inject(HttpTestingController).expectOne(() => true).flush({ ...payload, request_id: 'request-2' });
    await fixture.whenStable(); fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('Request details are not available');
    expect(fixture.nativeElement.textContent).not.toContain(payload.input_json);
  });
});
