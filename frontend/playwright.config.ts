import { defineConfig } from '@playwright/test';

const portValue = process.env['PLAYWRIGHT_PORT'] ?? '4200';
const port = Number(portValue);
if (!Number.isInteger(port) || port < 1 || port > 65_535) {
  throw new Error(
    `PLAYWRIGHT_PORT must be an integer from 1 to 65535; received ${JSON.stringify(portValue)}`,
  );
}

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
