/**
 * @file LocatorTable.test.ts
 * @brief Unit tests for formatLocatorValue helper.
 */

import { describe, it, expect } from "vitest";
import { formatLocatorValue } from "./LocatorTable";

describe("formatLocatorValue", () => {
  it("should format addresses and offsets in both decimal and hex", () => {
    expect(formatLocatorValue("file_offset", 1024)).toBe("1024 (0x400)");
    expect(formatLocatorValue("rva", 4096)).toBe("4096 (0x1000)");
  });

  it("should format non-offset numbers as standard numbers", () => {
    expect(formatLocatorValue("entries", 5)).toBe("5");
    expect(formatLocatorValue("version_code", 7)).toBe("7");
  });

  it("should format booleans and strings correctly", () => {
    expect(formatLocatorValue("signed", true)).toBe("true");
    expect(formatLocatorValue("package", "com.test")).toBe("com.test");
  });
});
