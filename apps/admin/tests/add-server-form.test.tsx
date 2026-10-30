import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { AddServerForm } from "@/components/add-server-form";

const mintJoinToken = vi.hoisted(() => vi.fn());
vi.mock("@/lib/node-actions", () => ({ mintJoinToken }));

describe("AddServerForm", () => {
  it("turns a name into the one command to run on the new server", async () => {
    mintJoinToken.mockResolvedValue({
      ok: true,
      data: {
        token: "v1.example",
        label: "amsterdam-1",
        expiresAt: "2026-10-29T12:00:00Z",
        apiUrl: "https://api.example.org:8444",
      },
    });
    const user = userEvent.setup();
    render(<AddServerForm />);

    await user.type(
      screen.getByLabelText("Name for the new server"),
      "Amsterdam 1",
    );
    await user.click(
      screen.getByRole("button", { name: "Create join command" }),
    );

    expect(mintJoinToken).toHaveBeenCalledWith("amsterdam-1");
    expect(
      await screen.findByLabelText("Command for the new server"),
    ).toHaveTextContent(
      "sudo ./install.sh --join https://api.example.org:8444 --token v1.example",
    );
  });

  it("shows why a token could not be made", async () => {
    mintJoinToken.mockResolvedValue({
      ok: false,
      code: "step_up_required",
      message: "Confirm with your authenticator code first.",
    });
    const user = userEvent.setup();
    render(<AddServerForm />);
    await user.type(screen.getByLabelText("Name for the new server"), "x");
    await user.click(
      screen.getByRole("button", { name: "Create join command" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Confirm with your authenticator code first.",
    );
  });
});
