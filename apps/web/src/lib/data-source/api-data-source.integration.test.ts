/**
 * @vitest-environment node
 * @file api-data-source.integration.test.ts
 * @brief Live integration test for ApiDataSource against a running `avero serve`.
 * @details Skipped unless AVERO_API_URL is set, e.g.
 *          AVERO_API_URL=http://127.0.0.1:8787 pnpm --filter web test
 */

import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { ApiDataSource } from "./api-data-source";

const baseUrl = process.env.AVERO_API_URL;
const liveDescribe = baseUrl ? describe : describe.skip;

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

liveDescribe("ApiDataSource live integration", () => {
  it("scans a fixture, streams a job result and reads report surfaces", async () => {
    const source = new ApiDataSource(baseUrl as string);
    const health = await source.health();
    expect(health.status).toBe("ok");
    expect(health.api_version).toBe("avero.api/v1");

    const fixturePath = path.resolve(process.cwd(), "../../tests/fixtures/sample.apk");
    const bytes = readFileSync(fixturePath);
    const file = new File([new Uint8Array(bytes)], "sample.apk", {
      type: "application/octet-stream",
    });
    const scan = await source.scan(file, { max_strings: 100 });
    expect(scan.job_id).toBeTruthy();

    let job = await source.getJob(scan.job_id);
    for (let attempt = 0; attempt < 200 && job.status !== "done" && job.status !== "failed"; attempt++) {
      await sleep(100);
      job = await source.getJob(scan.job_id);
    }
    expect(job.status).toBe("done");
    const reportId = job.result?.report_id as string;
    expect(reportId).toHaveLength(64);

    const report = await source.getReport(reportId);
    expect(report.schema_id).toBe("avero.report/v1");
    expect(report.artifact.kinds).toContain("apk");

    const manifest = await source.getApkManifest(reportId);
    expect(manifest.package).toBe("com.avero.testsample");

    const strings = await source.getStrings(reportId, { limit: 2, q: "Manifest" });
    expect(strings.items.length).toBeGreaterThan(0);

    const hex = await source.getHex(reportId, 0, 4);
    expect(hex?.bytes.length).toBe(4);

    const engines = await source.getEngines();
    expect(Array.isArray(engines)).toBe(true);

    const disassembly = await source.getDisassembly(reportId, { limit: 2 });
    expect(disassembly.items.length).toBeGreaterThan(0);
  }, 60_000);
});
