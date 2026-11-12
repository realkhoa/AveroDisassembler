import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
import path from "node:path";

/**
 * @file api-mode.spec.ts
 * @brief M2–M4 API-mode flows with the local avero serve API mocked by Playwright routes.
 */

const REPORT = JSON.parse(
  readFileSync(path.resolve(process.cwd(), "../../docs/api/sample-report.json"), "utf8"),
) as { artifact: { id: string } };
const REPORT_ID = REPORT.artifact.id;
const API_BASE = "http://127.0.0.1:8787";

function json(body: unknown, status = 200) {
  return {
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  };
}

test.beforeEach(async ({ context, page }) => {
  await context.addInitScript(
    ({ apiBase }) => {
      window.localStorage.setItem("avero_adapter_mode", "API");
      window.localStorage.setItem("avero_api_url", apiBase);
    },
    { apiBase: API_BASE },
  );

  await page.route("**/api/health", (route) =>
    route.fulfill(
      json({
        status: "ok",
        core_version: "0.12.0",
        api_version: "avero.api/v1",
        engines: { ilspycmd: true, ghidra: true, rizin: true, jadx: false },
      }),
    ),
  );
  await page.route(`**/api/reports/${REPORT_ID}`, (route) => route.fulfill(json(REPORT)));
});

test("api mode scans an artifact over SSE and opens the report", async ({ page }) => {
  const scanFile = path.resolve(process.cwd(), "../../tests/fixtures/sample.apk");

  await page.route("**/api/scans", (route) =>
    route.fulfill(json({ job_id: "job-e2e", status: "queued" }, 202)),
  );
  await page.route("**/api/jobs/job-e2e/events", (route) =>
    route.fulfill({
      status: 200,
      headers: { "content-type": "text/event-stream", "cache-control": "no-cache" },
      body:
        `data: {"type":"progress","job_id":"job-e2e","stage":"analyze","percent":50,"message":"running analyzers"}\n\n` +
        `data: {"type":"done","job_id":"job-e2e","report_id":"${REPORT_ID}"}\n\n`,
    }),
  );

  await page.goto("/");
  await expect(page.locator("header").getByText("API MODE", { exact: true })).toBeVisible();
  await expect(page.getByText("API READY")).toBeVisible();
  await expect(page.getByText(/Scan artifact with avero serve/i)).toBeVisible();

  await page.locator('input[type="file"]').setInputFiles(scanFile);
  await page.getByRole("button", { name: "Start scan" }).click();

  await page.waitForURL(new RegExp(`/report/${REPORT_ID}/overview`));
  await expect(page.getByText("sample.apk").first()).toBeVisible();
});

test("engines screen lists packs and installs through the API", async ({ page }) => {
  await page.route("**/api/engines", (route) =>
    route.fulfill(
      json({
        items: [
          {
            id: "rizin",
            name: "rizin",
            version: "0.9.1",
            license: "LGPL-3.0",
            integration: "sidecar",
            installed: true,
            binary: "engines/rizin/0.9.1/bin/rizin.exe",
            homepage: "https://rizin.re",
          },
          {
            id: "jadx",
            name: "jadx",
            version: "1.5.6",
            license: "Apache-2.0",
            integration: "sidecar",
            installed: false,
            binary: null,
            homepage: "https://github.com/skylot/jadx",
          },
        ],
      }),
    ),
  );

  await page.goto("/engines");
  await expect(page.getByRole("heading", { name: "Engine Packs" })).toBeVisible();
  await expect(page.getByText("rizin").first()).toBeVisible();
  await expect(page.getByText("jadx").first()).toBeVisible();
  await expect(page.getByText("not installed")).toBeVisible();
});

test("disassembly screen renders rizin-backed instructions", async ({ page }) => {
  await page.route(`**/api/reports/${REPORT_ID}/disassembly**`, (route) =>
    route.fulfill(
      json({
        address: "0x1400019c0",
        items: [
          {
            address: 5368715712,
            bytes_hex: "4883ec28",
            mnemonic: "sub",
            operands: "rsp, 0x28",
            size: 4,
            kind: "sub",
          },
          {
            address: 5368715716,
            bytes_hex: "e8cf050000",
            mnemonic: "call",
            operands: "0x140001f98",
            size: 5,
            kind: "call",
          },
        ],
        total: 2,
        next_cursor: null,
      }),
    ),
  );

  await page.goto(`/report/${REPORT_ID}/disassembly`);
  await expect(page.getByText(/0x1400019c0/).first()).toBeVisible();
  await expect(page.getByText(/sub rsp, 0x28/).first()).toBeVisible();
  await expect(page.getByText(/call 0x140001f98/).first()).toBeVisible();
});

test("diff screen compares two reports", async ({ page }) => {
  await page.route("**/api/diffs", (route) =>
    route.fulfill(
      json({
        schema_id: "avero.diff/v1",
        old: { report_id: REPORT_ID, size: 100, findings: 1, kinds: ["apk"] },
        new: { report_id: REPORT_ID, size: 120, findings: 2, kinds: ["apk"] },
        size_delta: 20,
        findings: {
          added: [
            {
              id: "F-1",
              severity: "high",
              category: "android",
              title: "Added finding",
              detail: "",
              evidence_ids: [],
              confidence: 0.9,
            },
          ],
          removed: [],
          unchanged: 0,
          counts: { added: 1, removed: 0, unchanged: 0 },
        },
        sections: { added: [], removed: [] },
        imports: { added: [], removed: [] },
        exports: { added: [], removed: [] },
        signatures: { added: [], removed: [] },
        metadata: { changed: [{ key: "zip_entries", old: 1, new: 2 }] },
        kinds: { old: ["apk"], new: ["apk"] },
      }),
    ),
  );

  await page.goto(`/report/${REPORT_ID}/diff`);
  const inputs = page.getByPlaceholder("artifact SHA-256");
  await inputs.nth(0).fill(REPORT_ID);
  await inputs.nth(1).fill(REPORT_ID);
  await page.getByRole("button", { name: "Compare" }).click();

  await expect(page.getByText(/Size delta/i)).toBeVisible();
  await expect(page.getByText(/\+20 bytes/)).toBeVisible();
  await expect(page.getByText("Added finding")).toBeVisible();
});

test("decompile screen surfaces a missing-engine error", async ({ page }) => {
  await page.route(`**/api/reports/${REPORT_ID}/decompile`, (route) =>
    route.fulfill(
      json(
        { error: { code: "engine_missing", message: "Ghidra is not installed" } },
        409,
      ),
    ),
  );

  await page.goto(`/report/${REPORT_ID}/decompile`);
  await page.getByRole("button", { name: "Decompile" }).click();
  await expect(page.getByText(/Ghidra is not installed/i)).toBeVisible();
  await expect(page.getByText(/avero engine install/i)).toBeVisible();
});
