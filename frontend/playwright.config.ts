import { defineConfig } from '@playwright/test';

const port = Number(process.env['PLAYWRIGHT_PORT'] || 4200);

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: 1,
  use: {
    reducedMotion: 'reduce',
    baseURL: `http://127.0.0.1:${port}`,
    channel: process.env['PLAYWRIGHT_CHANNEL'] || 'chrome',
    viewport: { width: 1600, height: 1000 },
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
  webServer: {
    command: `npm start -- --host 127.0.0.1 --port ${port}`,
    url: `http://127.0.0.1:${port}`,
    reuseExistingServer: !process.env['CI'],
    timeout: 120000,
  },
});
