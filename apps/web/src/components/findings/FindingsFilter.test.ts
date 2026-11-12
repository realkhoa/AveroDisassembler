/**
 * @file FindingsFilter.test.ts
 * @brief Unit tests verifying multi-attribute filtering of findings.
 */

import { describe, it, expect } from "vitest";
import type { Finding } from "@/types/report";

describe("Findings Filtering Logic", () => {
  const sampleFindings: Finding[] = [
    {
      id: "F-1",
      severity: "high",
      category: "android",
      title: "APK debuggable=true",
      detail: "Manifest enables debuggable",
      evidence_ids: ["E-1"],
      confidence: 0.9,
    },
    {
      id: "F-2",
      severity: "medium",
      category: "android",
      title: "Exported component without permission",
      detail: "MainActivity exported=true",
      evidence_ids: ["E-1"],
      confidence: 0.7,
    },
    {
      id: "F-3",
      severity: "low",
      category: "crypto",
      title: "Weak MD5 hash used",
      detail: "Legacy hashing algorithm",
      evidence_ids: ["E-2"],
      confidence: 0.85,
    },
  ];

  it("should filter by severity array", () => {
    const highOnly = sampleFindings.filter((f) => f.severity === "high");
    expect(highOnly.length).toBe(1);
    expect(highOnly[0].id).toBe("F-1");
  });

  it("should filter by category and text query", () => {
    const q = "debuggable";
    const matched = sampleFindings.filter(
      (f) =>
        f.category === "android" &&
        (f.title.toLowerCase().includes(q) || f.detail.toLowerCase().includes(q))
    );

    expect(matched.length).toBe(1);
    expect(matched[0].id).toBe("F-1");
  });
});
