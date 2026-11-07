import { describe, expect, it } from "vitest";
import { formatCount, formatPercent, formatSize, timeAgo } from "../format.js";

describe("formatCount", () => {
  it("is exact beyond JavaScript's safe integer range", () => {
    expect(formatCount("18446744073709551615")).toBe("18,446,744,073,709,551,615");
    // What Number() would do to the same value, for contrast:
    expect(String(Number("18446744073709551615"))).toBe("18446744073709552000");
  });

  it("copes with missing or odd values", () => {
    expect(formatCount(null)).toBe("–");
    expect(formatCount("abc")).toBe("abc");
  });
});

describe("formatSize", () => {
  it("writes big powers of two as 2^n", () => {
    expect(formatSize("18446744073709551616")).toBe("2^64");
    expect(formatSize("256")).toBe("256");
    expect(formatSize("4294967296")).toBe("2^32");
  });
});

describe("formatPercent", () => {
  it("shows tiny non-zero usage instead of rounding to 0", () => {
    expect(formatPercent(0.000001)).toBe("<0.01%");
    expect(formatPercent(0)).toBe("0.00%");
    expect(formatPercent(83.33)).toBe("83.3%");
  });
});

describe("timeAgo", () => {
  it("is relative to now", () => {
    const now = Date.parse("2026-11-07T12:00:00Z");
    expect(timeAgo("2026-11-07T11:58:00Z", now)).toBe("2 minutes ago");
    expect(timeAgo(null, now)).toBe("never");
  });
});
