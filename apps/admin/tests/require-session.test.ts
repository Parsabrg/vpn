import { afterEach, describe, expect, it, vi } from "vitest";

const redirectMock = vi.fn((url: string) => {
  throw new Error(`REDIRECT:${url}`);
});
vi.mock("next/navigation", () => ({
  redirect: redirectMock,
}));

const getAdminSessionMock = vi.fn();
vi.mock("@/lib/auth/session", () => ({
  getAdminSession: getAdminSessionMock,
}));

afterEach(() => {
  vi.clearAllMocks();
});

describe("requireAdminSession", () => {
  it("redirects to /login?reason=expired when there is no session", async () => {
    getAdminSessionMock.mockResolvedValue(null);
    const { requireAdminSession } = await import("@/lib/auth/require-session");

    await expect(requireAdminSession()).rejects.toThrow(
      "REDIRECT:/login?reason=expired",
    );
    expect(redirectMock).toHaveBeenCalledWith("/login?reason=expired");
  });

  it("returns the session and does not redirect when one exists", async () => {
    const session = { adminId: "1", role: "owner" as const, stepUp: false };
    getAdminSessionMock.mockResolvedValue(session);
    const { requireAdminSession } = await import("@/lib/auth/require-session");

    await expect(requireAdminSession()).resolves.toEqual(session);
    expect(redirectMock).not.toHaveBeenCalled();
  });
});
