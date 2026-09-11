import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ActivatedRoute, Router } from '@angular/router';
import { of } from 'rxjs';

import { UsersService } from '../settings/users.service';
import { AcceptInvitationPage } from './accept-invitation-page';

interface MockUsers {
  acceptInvitation: ReturnType<typeof vi.fn>;
}

interface MockRouter {
  navigate: ReturnType<typeof vi.fn>;
}

interface Rendered {
  component: AcceptInvitationPage;
  users: MockUsers;
  router: MockRouter;
  text(): string;
  fill(values: { password: string; confirm: string }): void;
  submit(): Promise<void>;
}

describe('AcceptInvitationPage', () => {
  let fixture: ComponentFixture<AcceptInvitationPage>;

  function element(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  function input(name: 'password' | 'confirm'): HTMLInputElement {
    const found = element().querySelector<HTMLInputElement>(`[formcontrolname="${name}"]`);
    if (!found) {
      throw new Error(`missing [formcontrolname="${name}"]`);
    }
    return found;
  }

  async function settle(): Promise<void> {
    await fixture.whenStable();
    fixture.detectChanges();
  }

  async function render(options: { fragment: string | null }): Promise<Rendered> {
    const users: MockUsers = { acceptInvitation: vi.fn().mockResolvedValue(undefined) };
    const router: MockRouter = { navigate: vi.fn().mockResolvedValue(true) };

    await TestBed.configureTestingModule({
      imports: [AcceptInvitationPage],
      providers: [
        { provide: UsersService, useValue: users },
        { provide: Router, useValue: router },
        { provide: ActivatedRoute, useValue: { fragment: of(options.fragment) } },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(AcceptInvitationPage);
    fixture.detectChanges();
    await settle();

    return {
      component: fixture.componentInstance,
      users,
      router,
      text: () => (element().textContent ?? '').replace(/\s+/g, ' ').trim(),
      fill: ({ password, confirm }) => {
        input('password').value = password;
        input('password').dispatchEvent(new Event('input'));
        input('confirm').value = confirm;
        input('confirm').dispatchEvent(new Event('input'));
        fixture.detectChanges();
      },
      submit: async () => {
        element().querySelector('form')?.dispatchEvent(new Event('submit'));
        await settle();
      },
    };
  }

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('reads the token from the fragment', async () => {
    const page = await render({ fragment: 'token=abc123' });
    expect(page.component.hasToken()).toBe(true);
  });

  it('clears the token from the address bar on load', async () => {
    const replaceState = vi.spyOn(history, 'replaceState');
    await render({ fragment: 'token=abc123' });
    expect(replaceState).toHaveBeenCalledTimes(1);
    const url = String(replaceState.mock.calls[0][2]);
    expect(url).not.toContain('#');
    expect(url).not.toContain('abc123');
  });

  it('shows the failure message when there is no fragment', async () => {
    const page = await render({ fragment: null });
    expect(page.component.hasToken()).toBe(false);
    expect(page.text()).toContain('invalid or has expired');
    // Not merely disabled: there is no form to submit at all.
    expect(element().querySelector('form')).toBeNull();
  });

  it('refuses a mismatched confirmation without calling the API', async () => {
    const page = await render({ fragment: 'token=abc123' });
    page.fill({ password: 'a-long-enough-password', confirm: 'something-else' });
    await page.submit();
    expect(page.users.acceptInvitation).not.toHaveBeenCalled();
  });

  it('submits the token in the body and redirects to login', async () => {
    const page = await render({ fragment: 'token=abc123' });
    page.fill({ password: 'a-long-enough-password', confirm: 'a-long-enough-password' });
    await page.submit();
    expect(page.users.acceptInvitation).toHaveBeenCalledWith('abc123', 'a-long-enough-password');
    expect(page.router.navigate).toHaveBeenCalledWith(['/login']);
  });

  it('shows the same indistinct message when the API call fails', async () => {
    const page = await render({ fragment: 'token=abc123' });
    page.users.acceptInvitation.mockRejectedValue(new Error('nope'));
    page.fill({ password: 'a-long-enough-password', confirm: 'a-long-enough-password' });
    await page.submit();
    expect(page.text()).toContain('invalid or has expired');
    expect(page.router.navigate).not.toHaveBeenCalled();
  });
});
