import { test, expect } from '@playwright/test';

test('Mist MFA opens a focused modal after the API challenge and supports retry and cancellation', async ({ page }) => {
  const attempts = [];
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/v1/health') return route.fulfill({ json: { version: 'test' } });
    if (path === '/api/v1/auth/bootstrap') return route.fulfill({ json: { available: false } });
    if (path === '/api/v1/auth/login/mist') {
      attempts.push(route.request().postDataJSON());
      return route.fulfill({ status: 409, json: { detail: { code: 'mist_mfa_required' } } });
    }
    return route.fulfill({ status: 401, json: { detail: 'Not authenticated' } });
  });
  await page.goto('/login');
  await page.getByRole('button', { name: 'Sign in with Mist', exact: true }).click();
  await expect(page.getByRole('dialog')).not.toBeVisible();
  const email = page.locator('#login-form input[name="username"]');
  const password = page.locator('#login-form input[name="password"]');
  await email.fill('admin@example.com');
  await password.fill('test password');
  await password.press('Enter');
  const dialog = page.getByRole('dialog');
  await expect(dialog).toBeVisible();
  const code = dialog.getByLabel('MIST VERIFICATION CODE');
  await expect(code).toBeFocused();
  expect(attempts).toEqual([{ email: 'admin@example.com', password: 'test password', region: 'global_01' }]);
  await code.fill('123456');
  await code.press('Enter');
  await expect(dialog).toContainText('not accepted');
  expect(attempts[1].two_factor).toBe('123456');
  await expect(code).toHaveValue('');
  await code.press('Escape');
  await expect(dialog).not.toBeVisible();
  await expect(password).toHaveValue('');
  await expect(page.getByRole('alert')).toContainText('cancelled');
});
