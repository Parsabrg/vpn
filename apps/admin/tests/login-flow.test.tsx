import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LoginFlow } from "@/components/login-flow";

const pushMock = vi.fn();
const refreshMock = vi.fn();

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock, refresh: refreshMock }),
}));

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
    ...init,
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
  pushMock.mockClear();
  refreshMock.mockClear();
});

describe("LoginFlow", () => {
  it("submits credentials and moves to the MFA step via keyboard", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse({
        challenge: "v1.challenge",
        next_step: "mfa",
        expires_in: 300,
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();

    render(<LoginFlow />);

    await user.type(
      screen.getByLabelText("Email or username"),
      "owner@example.com",
    );
    await user.type(
      screen.getByLabelText("Password"),
      "correct-password-canary",
    );
    await user.keyboard("{Enter}");

    await waitFor(() => {
      expect(screen.getByText(/6-digit code/i)).toBeVisible();
    });
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/admin/auth/login",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("shows an inline error and lets the admin retry", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({ detail: "Authentication was not accepted" }),
        {
          status: 401,
        },
      ),
    );
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();

    render(<LoginFlow />);

    await user.type(
      screen.getByLabelText("Email or username"),
      "owner@example.com",
    );
    await user.type(screen.getByLabelText("Password"), "wrong-password-canary");
    await user.click(screen.getByRole("button", { name: "Continue" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Authentication was not accepted",
    );
  });

  it("redirects to the dashboard once MFA succeeds", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({
          challenge: "v1.challenge",
          next_step: "mfa",
          expires_in: 300,
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          admin_id: "1",
          role: "owner",
          csrf_token: "v1.csrf",
          step_up: false,
        }),
      );
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();

    render(<LoginFlow />);

    await user.type(
      screen.getByLabelText("Email or username"),
      "owner@example.com",
    );
    await user.type(
      screen.getByLabelText("Password"),
      "correct-password-canary",
    );
    await user.click(screen.getByRole("button", { name: "Continue" }));

    const codeField = await screen.findByLabelText("Authentication code");
    await user.type(codeField, "123456");
    await user.click(screen.getByRole("button", { name: "Verify" }));

    await waitFor(() => {
      expect(pushMock).toHaveBeenCalledWith("/");
    });
    expect(refreshMock).toHaveBeenCalled();
  });
});
