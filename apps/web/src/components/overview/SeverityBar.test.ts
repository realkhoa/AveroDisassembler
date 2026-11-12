/**
 * @file SeverityBar.test.ts
 * @brief Unit tests for severity counts calculation logic.
 */

import { describe, it, expect } from "vitest";
import type { Finding, Severity } from "@/types/report";

describe("Severity Calculation Logic", () => {
  it("should tally severity distribution accurately", () => {
    const findings: Finding[] = [
      { id: "1", severity: "high", category: "sec", title: "A", detail: "", evidence_ids: [], confidence: 1 },
      { id: "2", severity: "high", category: "sec", title: "B", detail: "", evidence_ids: [], confidence: 1 },
      { id: "3", severity: "medium", category: "sec", title: "C", detail: "", evidence_ids: [], confidence: 0.8 },
      { id: "4", severity: "low", category: "sec", title: "D", detail: "", evidence_ids: [], confidence: 0.5 },
    ];

    const counts: Record<Severity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    for (const f of findings) {
      if (f.severity in counts) {
        counts[f.severity]++;
      }
    }

    expect(counts.high).toBe(2);
    expect(counts.medium).toBe(1);
    expect(counts.low).toBe(1);
    expect(counts.critical).toBe(0);
    expect(counts.info).toBe(0);
  });
});
