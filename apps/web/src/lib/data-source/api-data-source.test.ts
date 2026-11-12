/**
 * @file api-data-source.test.ts
 * @brief Unit tests for the API-mode data source (fetch mocked; no daemon required).
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiDataSource } from "./api-data-source";

const BASE = "http://127.0.0.1:8787";

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? "OK" : "Error",
    json: async () => body,
  } as unknown as Response;
}

describe("ApiDataSource", () => {
  let source: ApiDataSource;
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    source = new ApiDataSource(`${BASE}/`);
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });

  it("reports health", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        status: "ok",
        core_version: "0.11.0",
        api_version: "avero.api/v1",
        engines: { rizin: true },
      }),
    );
    const health = await source.health();
    expect(health.api_version).toBe("avero.api/v1");
    expect(fetchMock).toHaveBeenCalledWith(`${BASE}/api/health`, expect.anything());
  });

  it("fetches a report by id", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ schema_id: "avero.report/v1", artifact: { id: "abc" } }));
    const report = await source.getReport("abc");
    expect(report.artifact.id).toBe("abc");
    expect(fetchMock.mock.calls[0][0]).toBe(`${BASE}/api/reports/abc`);
  });

  it("builds paged finding queries", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ items: [{ id: "F-1", severity: "high", title: "x" }], total: 1, next_cursor: null }),
    );
    const page = await source.getFindings("abc", { severity: "high", q: "x", limit: 10 });
    expect(page.total).toBe(1);
    const url = fetchMock.mock.calls[0][0] as string;
    expect(url).toContain("/api/reports/abc/findings?");
    expect(url).toContain("severity=high");
    expect(url).toContain("q=x");
    expect(url).toContain("limit=10");
  });

  it("builds paged string queries", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ items: [{ offset: 1, value: "hi", encoding: "ascii" }], total: 1, next_cursor: null }),
    );
    const page = await source.getStrings("abc", { q: "hi", encoding: "ascii", offset: 10, limit: 5 });
    expect(page.total).toBe(1);
    const url = fetchMock.mock.calls[0][0] as string;
    expect(url).toContain("/api/reports/abc/strings?");
    expect(url).toContain("q=hi");
    expect(url).toContain("offset=10");
    expect(url).toContain("limit=5");
  });

  it("decodes base64 hex slices", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ offset: 4, length: 4, bytes_base64: btoa("ABCD") }),
    );
    const slice = await source.getHex("abc", 4, 4);
    expect(slice).not.toBeNull();
    expect(slice?.bytes.length).toBe(4);
    expect(Array.from(slice?.bytes || [])).toEqual([65, 66, 67, 68]);
  });

  it("posts decompile requests with engine and type", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ job_id: "job-1", status: "queued" }, 202));
    const job = await source.decompile("abc", { engine: "ghidra", type: "entry", limit: 2 });
    expect(job.job_id).toBe("job-1");
    const [, init] = fetchMock.mock.calls[0];
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({ engine: "ghidra", type: "entry", limit: 2 });
  });

  it("posts diff requests", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ schema_id: "avero.diff/v1", size_delta: 10 }));
    const diff = await source.diff("old", "new");
    expect(diff.schema_id).toBe("avero.diff/v1");
    expect(fetchMock.mock.calls[0][0]).toBe(`${BASE}/api/diffs`);
  });

  it("surfaces API error envelopes", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ error: { code: "engine_missing", message: "rizin is not installed" } }, 409),
    );
    await expect(source.getDisassembly("abc")).rejects.toThrow(/rizin is not installed/);
  });
});
