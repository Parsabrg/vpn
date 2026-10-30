import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import {
  TrafficAllowancePanel,
  formatBytes,
} from "@/components/traffic-allowance-panel";
import type { TrafficAllowance } from "@/lib/users";

const grantTrafficQuota = vi.hoisted(() => vi.fn());

vi.mock("@/lib/users-actions", () => ({
  grantTrafficQuota,
}));

const GIB = 1024 ** 3;

function allowance(
  overrides: Partial<TrafficAllowance> = {},
): TrafficAllowance {
  return {
    usedBytes: 40 * GIB,
    quotaBytes: 100 * GIB,
    remainingBytes: 60 * GIB,
    exhaustedAt: null,
    lifetimeBytes: 140 * GIB,
    ...overrides,
  };
}

describe("formatBytes", () => {
  it("uses binary units, matching what the servers count", () => {
    // 1000 MB is not a gigabyte here. Mixing conventions turns a "1 GB"
    // allowance into an argument about seven per cent of it.
    expect(formatBytes(GIB)).toBe("1.0 GB");
    expect(formatBytes(1000 * 1024 ** 2)).toBe("1000 MB");
  });

  it("keeps one decimal below ten and none above", () => {
    expect(formatBytes(412 * GIB)).toBe("412 GB");
    expect(formatBytes(Math.round(1.4 * GIB))).toBe("1.4 GB");
  });

  it("never renders a negative size", () => {
    expect(formatBytes(-5)).toBe("0 B");
  });
});

describe("the allowance panel", () => {
  it("shows what is left and what has ever been transferred", () => {
    // The lifetime figure is there so a top-up does not look like the
    // history was deleted.
    render(
      <TrafficAllowancePanel userId="u1" initialAllowance={allowance()} />,
    );

    expect(screen.getByText("100 GB")).toBeInTheDocument();
    expect(screen.getByText("40 GB")).toBeInTheDocument();
    expect(screen.getByText("60 GB")).toBeInTheDocument();
    expect(screen.getByText("140 GB")).toBeInTheDocument();
  });

  it("an unmetered account shows no remaining figure at all", () => {
    // Any number here would be an invented limit.
    render(
      <TrafficAllowancePanel
        userId="u1"
        initialAllowance={allowance({
          quotaBytes: null,
          remainingBytes: null,
        })}
      />,
    );

    expect(screen.getByText("Unmetered")).toBeInTheDocument();
    expect(screen.getByText("—")).toBeInTheDocument();
  });

  it("says when an account was cut off, and that a grant restores it", () => {
    render(
      <TrafficAllowancePanel
        userId="u1"
        initialAllowance={allowance({
          usedBytes: 100 * GIB,
          remainingBytes: 0,
          exhaustedAt: "2026-09-11T12:00:00Z",
        })}
      />,
    );

    expect(screen.getByRole("status")).toHaveTextContent(
      /credentials were revoked/i,
    );
    expect(
      screen.getByRole("button", { name: /grant a new allowance/i }),
    ).toBeInTheDocument();
  });

  it("an unmetered account is not offered a limit to remove", () => {
    render(
      <TrafficAllowancePanel
        userId="u1"
        initialAllowance={allowance({ quotaBytes: null, remainingBytes: null })}
      />,
    );

    expect(
      screen.queryByRole("button", { name: /remove the limit/i }),
    ).not.toBeInTheDocument();
  });

  it("grants the amount in the unit chosen, in binary bytes", async () => {
    // The whole point of the control: an operator types the size of the plan
    // they sold, and the system stores that many bytes.
    grantTrafficQuota.mockResolvedValue({ ok: true, data: allowance() });
    const user = userEvent.setup();
    render(
      <TrafficAllowancePanel userId="u1" initialAllowance={allowance()} />,
    );

    await user.click(screen.getByRole("button", { name: /change allowance/i }));
    const amount = screen.getByLabelText("Allowance");
    await user.clear(amount);
    await user.type(amount, "200");
    await user.click(screen.getByRole("button", { name: "Grant" }));

    expect(grantTrafficQuota).toHaveBeenCalledWith("u1", 200 * GIB);
  });

  it("removing the limit sends null, not zero", async () => {
    // Null is unmetered and zero is "nothing allowed" -- opposites that both
    // read as "no number of gigabytes".
    grantTrafficQuota.mockResolvedValue({
      ok: true,
      data: allowance({ quotaBytes: null, remainingBytes: null }),
    });
    const user = userEvent.setup();
    render(
      <TrafficAllowancePanel userId="u1" initialAllowance={allowance()} />,
    );

    await user.click(screen.getByRole("button", { name: /remove the limit/i }));
    await user.click(screen.getByRole("button", { name: "Remove limit" }));

    expect(grantTrafficQuota).toHaveBeenCalledWith("u1", null);
  });

  it("warns that the count starts again, naming what is written off", async () => {
    const user = userEvent.setup();
    render(
      <TrafficAllowancePanel userId="u1" initialAllowance={allowance()} />,
    );

    await user.click(screen.getByRole("button", { name: /change allowance/i }));

    expect(screen.getByText(/count starts again at\s+zero/i)).toHaveTextContent(
      "40 GB used so far will no longer count against it",
    );
  });
});
