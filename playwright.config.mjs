import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/e2e",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 90000,
  expect: { timeout: 15000 },
  reporter: [["list"], ["html", { open: "never" }]],
  use: {
    baseURL: "http://localhost:3001",
    actionTimeout: 15000,
    timezoneId: "America/Sao_Paulo",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: "npm run dev --workspace=@neoguardian/web -- --hostname 127.0.0.1 --port 3001",
    url: "http://localhost:3001/login",
    reuseExistingServer: false,
    timeout: 120000,
    env: {
      NEXT_PUBLIC_API_URL: "http://localhost:8001/api/v1",
      INTERNAL_API_URL: "http://localhost:8001/api/v1",
      TZ: "UTC",
    },
  },
});
