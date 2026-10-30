import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import {
  ReconcileNowControl,
  describeReconciliation,
} from "@/components/reconcile-now-control";

vi.mock("@/lib/topology-actions", () => ({ reconcileNow: vi.fn() }));

const zero = {
  checked: 0,
  inSync: 0,
  repaired: 0,
  repairFailed: 0,
  ambiguous: 0,
  errored: 0,
};

describe("ReconcileNowControl", () => {
  it("offers a full run without a target", () => {
    render(<ReconcileNowControl />);
    expect(
      screen.getByRole("button", { name: "Run reconciliation now" }),
    ).toBeTruthy();
  });

  it("offers to check one credential again", () => {
    render(<ReconcileNowControl targetId="t" />);
    expect(screen.getByRole("button", { name: "Check again" })).toBeTruthy();
  });

  it("sums both passes and leaves out what did not happen", () => {
    expect(
      describeReconciliation({
        wireguard: { ...zero, checked: 2, inSync: 2 },
        xray: { ...zero, checked: 12, inSync: 11, ambiguous: 1 },
      }),
    ).toBe("14 checked: 13 in sync, 1 ambiguous.");
  });

  it("says plainly when there was nothing to check", () => {
    expect(describeReconciliation({ wireguard: zero, xray: zero })).toBe(
      "0 checked.",
    );
  });
});
