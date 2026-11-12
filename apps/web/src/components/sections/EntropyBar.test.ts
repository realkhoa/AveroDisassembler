/**
 * @file EntropyBar.test.ts
 * @brief Unit tests for entropy clamping and risk threshold mapping.
 */

import { describe, it, expect } from "vitest";
import { getEntropyTone } from "./EntropyBar";

describe("Entropy Tone Logic", () => {
  it("should classify high entropy (>7.2) as Encrypted/Packed", () => {
    const tone = getEntropyTone(7.8);
    expect(tone.tag).toBe("Encrypted/Packed");
    expect(tone.textClass).toBe("text-critical");
  });

  it("should classify moderate entropy as Code/Data", () => {
    const tone = getEntropyTone(5.5);
    expect(tone.tag).toBe("Code/Data");
    expect(tone.textClass).toBe("text-medium");
  });

  it("should clamp values properly", () => {
    const toneHigh = getEntropyTone(10.0);
    expect(toneHigh.tag).toBe("Encrypted/Packed");

    const toneLow = getEntropyTone(-1.0);
    expect(toneLow.tag).toBe("Sparse");
  });
});
