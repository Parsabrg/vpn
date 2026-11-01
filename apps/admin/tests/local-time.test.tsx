import { render, screen } from "@testing-library/react";
import { renderToString } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { LocalTime, formatLocal, formatUtc } from "@/components/local-time";

const MOMENT = "2026-11-01T06:57:24Z";

describe("LocalTime", () => {
  it("renders the same text on the server whatever the server's zone", () => {
    // What the browser's first render must match: React error #418 came from
    // the server and the browser formatting in different zones.
    const html = renderToString(<LocalTime value={MOMENT} />);
    expect(html).toContain("2026-11-01 06:57 UTC");
    expect(formatUtc(new Date(MOMENT))).toBe("2026-11-01 06:57 UTC");
  });

  it("shows the viewer's local time, with the zone named, once in the browser", () => {
    render(<LocalTime value={MOMENT} />);
    const shown = screen.getByText(formatLocal(new Date(MOMENT)));
    expect(shown.tagName).toBe("TIME");
    expect(shown).toHaveAttribute("datetime", "2026-11-01T06:57:24.000Z");
    expect(shown).toHaveAttribute("title", "2026-11-01 06:57 UTC");
  });

  it("shows a dash for a value that is not a time", () => {
    render(<LocalTime value="not a date" />);
    expect(screen.getByText("—")).toBeInTheDocument();
  });
});
