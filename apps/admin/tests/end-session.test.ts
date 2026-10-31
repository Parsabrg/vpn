import { afterEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

vi.mock("server-only", () => ({}));
vi.mock("@/lib/api/config", () => ({
  apiBaseUrl: () => "http://api.internal:8000",
  adminOrigin: () => "https://panel.example.org",
}));

import { POST } from "@/app/api/admin/auth/logout/route";
import { endedSession } from "@/lib/end-session";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function logout(): Promise<Response> {
  return POST(
    new NextRequest("https://panel.example.org/api/admin/auth/logout", {
      method: "POST",
      headers: { cookie: "__Host-nebula_admin=s; __Host-nebula_csrf=spent" },
      body: "{}",
    }),
  );
}

describe("signing out", () => {
  it("clears the session cookies when the API refuses the logout", async () => {
    // A spent CSRF token: the API answers 401, and the browser must still
    // end up signed out rather than on pages whose buttons all fail.
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response('{"detail":"no"}', { status: 401 })),
    );

    const cleared = (await logout()).headers.getSetCookie().join("\n");

    expect(cleared).toContain("__Host-nebula_admin=;");
    expect(cleared).toContain("__Host-nebula_csrf=;");
    expect(cleared).toMatch(/Max-Age=0/i);
  });

  it("leaves a successful logout's own cookies alone", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(null, {
            status: 204,
            headers: {
              "set-cookie": "__Host-nebula_admin=; Max-Age=0; Path=/",
            },
          }),
      ),
    );

    const cookies = (await logout()).headers.getSetCookie();

    expect(cookies).toEqual(["__Host-nebula_admin=; Max-Age=0; Path=/"]);
  });
});

describe("an action that finds the session gone", () => {
  it("signs out and opens the sign-in page", async () => {
    const fetchMock = vi.fn(async () => new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetchMock);
    const assign = vi.fn();
    vi.stubGlobal("location", { ...window.location, assign });

    expect(endedSession({ ok: false, code: "signed_out" })).toBe(true);
    await vi.waitFor(() => {
      expect(assign).toHaveBeenCalledWith("/login?reason=expired");
    });
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/admin/auth/logout",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("leaves any other failure to the caller", () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    expect(endedSession({ ok: false, code: "conflict" })).toBe(false);
    expect(endedSession({ ok: true })).toBe(false);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
