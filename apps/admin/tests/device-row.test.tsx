import { describe, expect, it } from "vitest";
import { ago } from "@/components/device-row";

describe("ago", () => {
  const now = Date.parse("2026-10-13T12:00:00Z");

  it("says how long since the evidence", () => {
    expect(ago("2026-10-13T11:59:30Z", now)).toBe("30 s ago");
    expect(ago("2026-10-13T11:58:00Z", now)).toBe("2 min ago");
    expect(ago("2026-10-13T09:00:00Z", now)).toBe("3 h ago");
    expect(ago("2026-10-10T12:00:00Z", now)).toBe("3 d ago");
  });

  it("claims nothing without evidence", () => {
    expect(ago(null, now)).toBe("—");
  });
});
