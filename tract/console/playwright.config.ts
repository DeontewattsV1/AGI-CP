import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  use: {
    baseURL: "http://127.0.0.1:4173",
    viewport: { width: 1000, height: 1000 },
    colorScheme: "dark",
  },
  webServer: {
    command: "npm run preview -- --port 4173",
    port: 4173,
    reuseExistingServer: !process.env.CI,
  },
});
