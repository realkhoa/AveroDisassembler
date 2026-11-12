/**
 * @file report.test.ts
 * @brief Unit tests validating report contract types against fixture data.
 */

import { describe, it, expect } from "vitest";
import sampleReport from "../../../../docs/api/sample-report.json";
import type { AveroReport } from "./report";

describe("AveroReport Contract", () => {
  /**
   * @brief Verifies that sample-report.json conforms to the AveroReport schema.
   */
  it("should match schema_id avero.report/v1 and expected fields", () => {
    const report = sampleReport as unknown as AveroReport;
    expect(report.schema_id).toBe("avero.report/v1");
    expect(report.artifact.id).toBe("34e0af96df1949bf0c36f8fd7cfe9416bd645edc576a088ee8b31d52a7dd3f69");
    expect(report.artifact.kinds).toContain("apk");
    expect(report.findings.length).toBe(4);
    expect(report.artifact.evidence?.length).toBeGreaterThan(0);
    expect(report.coverage).toBeDefined();
  });
});
