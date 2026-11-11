import { formatDuration, timeAgo } from "./format";

describe("timeAgo", () => {
  const now = new Date("2026-11-11T12:00:00Z");
  it.each([
    ["2026-11-11T11:59:30Z", "now"],
    ["2026-11-11T11:22:00Z", "38m"],
    ["2026-11-11T10:00:00Z", "2h"],
    ["2026-11-08T12:00:00Z", "3d"],
  ])("%s -> %s", (iso, expected) => {
    expect(timeAgo(iso, now)).toBe(expected);
  });

  it("never shows a negative age when the clock is skewed", () => {
    expect(timeAgo("2026-11-11T12:05:00Z", now)).toBe("now");
  });
});

describe("formatDuration", () => {
  it("shows a dash when there is no data", () => expect(formatDuration(null)).toBe("—"));
  it("scales units", () => {
    expect(formatDuration(30)).toBe("30s");
    expect(formatDuration(600)).toBe("10m");
    expect(formatDuration(5400)).toBe("1.5h");
  });
});
