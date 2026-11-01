import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { AccessReadiness } from "@/components/access-readiness";

const refresh = vi.fn();
const grantPermissions = vi.hoisted(() => vi.fn());
const assignServer = vi.hoisted(() => vi.fn());

vi.mock("next/navigation", () => ({ useRouter: () => ({ refresh }) }));
vi.mock("@/lib/access-actions", () => ({ grantPermissions, assignServer }));
// The code dialog itself is tested on its own; here only that it opens and
// what happens once the code is verified.
vi.mock("@/components/step-up-modal", () => ({
  StepUpModal: ({
    open,
    onVerified,
  }: {
    open: boolean;
    onVerified: () => void;
  }) =>
    open ? (
      <button type="button" onClick={onVerified}>
        Verify code
      </button>
    ) : null,
}));

describe("AccessReadiness", () => {
  it("says nothing once the user can connect", () => {
    const { container } = render(
      <AccessReadiness
        userId="u1"
        hasProtocol
        hasServer
        missingProfileIds={[]}
        missingServerIds={[]}
      />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it("names what is missing and fixes both in a click each", async () => {
    grantPermissions.mockResolvedValue({ ok: true, data: [] });
    assignServer.mockResolvedValue({ ok: true, data: {} });
    const user = userEvent.setup();
    render(
      <AccessReadiness
        userId="u1"
        hasProtocol={false}
        hasServer={false}
        missingProfileIds={["p1", "p2"]}
        missingServerIds={["s1", "s2"]}
      />,
    );

    expect(screen.getByRole("status")).toHaveTextContent(
      "no protocol is granted and no server is assigned",
    );
    await user.click(
      screen.getByRole("button", { name: "Grant all protocols" }),
    );
    expect(grantPermissions).toHaveBeenCalledWith("u1", ["p1", "p2"]);
    await user.click(
      screen.getByRole("button", { name: "Assign all servers" }),
    );
    expect(assignServer.mock.calls).toEqual([
      ["u1", "s1"],
      ["u1", "s2"],
    ]);
    expect(refresh).toHaveBeenCalledTimes(2);
  });

  it("asks for the authenticator code and then does it", async () => {
    // 2026-11-01: these buttons only printed "Step-up verification is
    // required" and stopped.
    grantPermissions
      .mockResolvedValueOnce({
        ok: false,
        code: "step_up_required",
        message: "Step-up verification is required",
      })
      .mockResolvedValueOnce({ ok: true, data: [] });
    refresh.mockClear();
    const user = userEvent.setup();
    render(
      <AccessReadiness
        userId="u1"
        hasProtocol={false}
        hasServer
        missingProfileIds={["p1"]}
        missingServerIds={[]}
      />,
    );

    await user.click(
      screen.getByRole("button", { name: "Grant all protocols" }),
    );
    expect(screen.queryByRole("alert")).toBeNull();
    await user.click(screen.getByRole("button", { name: "Verify code" }));

    expect(grantPermissions).toHaveBeenCalledTimes(2);
    expect(refresh).toHaveBeenCalledTimes(1);
  });
});
