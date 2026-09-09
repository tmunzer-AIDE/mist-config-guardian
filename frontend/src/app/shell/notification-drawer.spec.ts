import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';

import { AppNotification, NotificationService } from '../core/notification.service';
import { OrganizationContextService } from '../core/organization-context.service';
import { NotificationDrawer } from './notification-drawer';

const organizationStub = { selected: signal({ id: 'org-1', name: 'Northwind Retail', status: 'verified' }) };

function notification(id: string, title: string): AppNotification {
  return {
    id,
    kind: 'restore',
    severity: 'info',
    title,
    body: 'Body',
    target: 'restore',
    target_params: { operation: id },
    mandatory: false,
    read_at: null,
    created_at: '2026-09-08T09:00:00Z',
  };
}

/**
 * The drawer declares itself a modal dialog, so the keyboard has to agree:
 * focus moves in, Tab stays in, Escape closes, and focus goes back out.
 */
describe('NotificationDrawer', () => {
  let fixture: ComponentFixture<NotificationDrawer>;
  let opener: HTMLButtonElement;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [NotificationDrawer],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        { provide: OrganizationContextService, useValue: organizationStub as unknown as OrganizationContextService },
      ],
    }).compileComponents();
    TestBed.inject(NotificationService).items.set([notification('n1', 'Restore completed'), notification('n2', 'Restore failed')]);

    // The bell, standing in: it has focus when the drawer opens.
    opener = document.createElement('button');
    opener.textContent = 'Notifications';
    document.body.append(opener);
    opener.focus();

    fixture = TestBed.createComponent(NotificationDrawer);
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
  });

  afterEach(() => {
    opener.remove();
  });

  function panel(): HTMLElement {
    return (fixture.nativeElement as HTMLElement).querySelector<HTMLElement>('.panel')!;
  }

  function buttons(): HTMLButtonElement[] {
    return Array.from(panel().querySelectorAll<HTMLButtonElement>('button'));
  }

  function key(target: HTMLElement, init: KeyboardEventInit): void {
    target.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true, cancelable: true, ...init }));
  }

  it('takes focus when it opens, instead of leaving it behind the scrim', () => {
    expect(document.activeElement).toBe(panel());
  });

  it('keeps Tab inside the dialog at both ends', () => {
    const all = buttons();
    const first = all[0];
    const last = all[all.length - 1];

    last.focus();
    key(last, { key: 'Tab' });
    expect(document.activeElement).toBe(first);

    key(first, { key: 'Tab', shiftKey: true });
    expect(document.activeElement).toBe(last);
  });

  it('closes on Escape from anywhere inside', () => {
    const closed = vi.fn();
    fixture.componentInstance.closed.subscribe(closed);

    buttons()[1].focus();
    key(buttons()[1], { key: 'Escape' });

    expect(closed).toHaveBeenCalledTimes(1);
  });

  it('gives focus back to the opener when it closes', () => {
    expect(document.activeElement).not.toBe(opener);

    fixture.destroy();

    expect(document.activeElement).toBe(opener);
  });
});
