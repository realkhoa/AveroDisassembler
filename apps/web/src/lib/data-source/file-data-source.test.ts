/**
 * @file file-data-source.test.ts
 * @brief Unit tests for FileDataSource implementation.
 */

import { describe, it, expect, beforeEach } from "vitest";
import sampleReport from "../../../../../docs/api/sample-report.json";
import { FileDataSource } from "./file-data-source";

describe("FileDataSource", () => {
  let source: FileDataSource;

  beforeEach(() => {
    source = new FileDataSource();
  });

  /**
   * @brief Verifies loading report JSON content into memory.
   */
  it("should load valid report json and resolve by artifact id", async () => {
    const jsonStr = JSON.stringify(sampleReport);
    const report = await source.loadReport(jsonStr);

    expect(report.artifact.id).toBe("34e0af96df1949bf0c36f8fd7cfe9416bd645edc576a088ee8b31d52a7dd3f69");
    const retrieved = await source.getReport(report.artifact.id);
    expect(retrieved.schema_id).toBe("avero.report/v1");
  });

  /**
   * @brief Verifies evidence lookup.
   */
  it("should resolve evidence by evidence ID", async () => {
    await source.loadReport(JSON.stringify(sampleReport));
    const evidence = await source.getEvidence(
      "34e0af96df1949bf0c36f8fd7cfe9416bd645edc576a088ee8b31d52a7dd3f69",
      "876660acc8f179af"
    );

    expect(evidence).not.toBeNull();
    expect(evidence?.producer.engine).toBe("avero.apk");
    expect(evidence?.locator.package).toBe("com.avero.testsample");
  });

  /**
   * @brief Verifies string querying and filtering.
   */
  it("should filter strings by search query and encoding", async () => {
    await source.loadReport(JSON.stringify(sampleReport));
    const page = await source.getStrings(
      "34e0af96df1949bf0c36f8fd7cfe9416bd645edc576a088ee8b31d52a7dd3f69",
      { q: "AndroidManifest" }
    );

    expect(page.items.length).toBeGreaterThanOrEqual(1);
    expect(page.items[0].value).toContain("AndroidManifest.xml");
  });

  /**
   * @brief Verifies hex slicing behavior with and without raw bytes.
   */
  it("should return null when raw artifact bytes are missing, and slice when attached", async () => {
    const reportId = "34e0af96df1949bf0c36f8fd7cfe9416bd645edc576a088ee8b31d52a7dd3f69";
    await source.loadReport(JSON.stringify(sampleReport));

    const hexMissing = await source.getHex(reportId, 0, 16);
    expect(hexMissing).toBeNull();

    const dummyBytes = new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00]);
    source.setArtifactBytes(reportId, dummyBytes);

    const hexSlice = await source.getHex(reportId, 0, 4);
    expect(hexSlice).not.toBeNull();
    expect(hexSlice?.length).toBe(4);
    expect(hexSlice?.bytes[0]).toBe(0x50);
    expect(hexSlice?.bytes[1]).toBe(0x4b);
  });
});
