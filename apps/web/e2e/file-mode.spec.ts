import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

/**
 * @file file-mode.spec.ts
 * @brief M1 file-mode report viewer flows and accessibility.
 */

const SAMPLE_REPORT_ID = "34e0af96df1949bf0c36f8fd7cfe9416bd645edc576a088ee8b31d52a7dd3f69";

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    window.localStorage.setItem("avero_adapter_mode", "FILE");
    window.localStorage.removeItem("avero_api_url");
  });
});

test("home page renders and opens the sample report", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Avero Disassembler Workbench" })).toBeVisible();
  await expect(page.getByText("FILE MODE")).toBeVisible();

  await page.getByRole("button", { name: /Open Sample Report/i }).click();
  await page.waitForURL(new RegExp(`/report/${SAMPLE_REPORT_ID}/overview`));

  await expect(page.getByText("sample.apk").first()).toBeVisible();
  await expect(page.getByText(/APK debuggable=true/i).first()).toBeVisible();
  await expect(page.getByText(/Top Findings/i)).toBeVisible();
  await expect(page.getByText(/SHA-256/i).first()).toBeVisible();
});

test("findings, evidence and sections screens read the loaded report", async ({ page }) => {
  await page.goto(`/report/${SAMPLE_REPORT_ID}/overview`);

  await page.locator("aside").getByRole("link", { name: /Findings/ }).click();
  await page.waitForURL(/\/findings/);
  await expect(page.getByText(/APK debuggable=true/i).first()).toBeVisible();
  await expect(page.getByText(/not signed/i).first()).toBeVisible();

  await page.locator("aside").getByRole("link", { name: "Evidence" }).click();
  await page.waitForURL(/\/evidence/);
  await expect(page.getByText(/Evidence/i).first()).toBeVisible();

  await page.locator("aside").getByRole("link", { name: "Sections" }).click();
  await page.waitForURL(/\/sections/);
  await expect(page.getByText(/Sections/i).first()).toBeVisible();
});

test("settings switches to API mode and persists the choice", async ({ page }) => {
  await page.route("**/api/health", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        status: "ok",
        core_version: "0.12.0",
        api_version: "avero.api/v1",
        engines: {},
      }),
    }),
  );
  await page.goto("/settings");
  await expect(page.getByRole("heading", { name: "Workbench Settings" })).toBeVisible();

  await page.getByRole("radio", { name: /API Mode/i }).check();
  await page.getByRole("button", { name: "Save Changes" }).click();
  await expect(page.locator("header").getByText("API MODE", { exact: true })).toBeVisible();
  await expect
    .poll(() => page.evaluate(() => window.localStorage.getItem("avero_adapter_mode")))
    .toBe("API");
  await expect(page.getByText("API READY")).toBeVisible();
});

test("home has no serious or critical accessibility violations", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Avero Disassembler Workbench" })).toBeVisible();
  const results = await new AxeBuilder({ page }).analyze();
  const serious = results.violations.filter(
    (violation) => violation.impact === "serious" || violation.impact === "critical",
  );
  expect(
    serious,
    serious.map((violation) => `${violation.id}: ${violation.nodes.length} node(s)`).join("\n"),
  ).toEqual([]);
});

test("overview has no serious or critical accessibility violations", async ({ page }) => {
  await page.goto(`/report/${SAMPLE_REPORT_ID}/overview`);
  await expect(page.getByText("sample.apk").first()).toBeVisible();
  const results = await new AxeBuilder({ page }).analyze();
  const serious = results.violations.filter(
    (violation) => violation.impact === "serious" || violation.impact === "critical",
  );
  expect(
    serious,
    serious.map((violation) => `${violation.id}: ${violation.nodes.length} node(s)`).join("\n"),
  ).toEqual([]);
});

test("unknown report deep link shows a friendly error instead of a spinner", async ({ page }) => {
  const unknownId = "0".repeat(64);
  await page.goto(`/report/${unknownId}/overview`);
  await expect(page.getByText("Report not available")).toBeVisible();
  await expect(page.getByRole("link", { name: /Back to Home/i })).toBeVisible();
});