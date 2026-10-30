import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { RecoveryCodesRotate } from "@/components/recovery-codes-rotate";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("RecoveryCodesRotate", () => {
  it("asks first, then shows the new codes one per line", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ recovery_codes: ["v1.one", "v1.two"] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    render(<RecoveryCodesRotate />);

    await user.click(
      screen.getByRole("button", { name: "Generate new recovery codes" }),
    );
    expect(fetchMock).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Replace my codes" }));

    const list = await screen.findByRole("list", { name: "Recovery codes" });
    expect(
      [...list.querySelectorAll("li")].map((item) => item.textContent),
    ).toEqual(["v1.one", "v1.two"]);
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/admin/auth/recovery-codes/rotate",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("says what to do when the session needs a fresh code", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response("{}", { status: 403 })),
    );
    const user = userEvent.setup();
    render(<RecoveryCodesRotate />);
    await user.click(
      screen.getByRole("button", { name: "Generate new recovery codes" }),
    );
    await user.click(screen.getByRole("button", { name: "Replace my codes" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Sign in again with your authenticator code",
    );
  });
});
