import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "tests",
  timeout: 90_000,
  workers: 1,
  reporter: [["list"]],
  globalSetup: "./setup.ts",
  use: { baseURL: "http://localhost:18182" },
});
