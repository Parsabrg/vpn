import { afterEach, describe, expect, it, vi } from "vitest";

// Found in production: the step-up box rejected every correct code. Each
// admin mutation spends the CSRF token and issues the next, a refused one
// included; this client dropped the replacement, so the browser kept sending
// the spent token and the verification was refused before its code was read.

const store = {
  getAll: vi.fn(() => [
    { name: "__Host-nebula_admin", value: "session" },
    { name: "__Host-nebula_csrf", value: "spent" },
  ]),
  get: vi.fn((name: string) =>
    name === "__Host-nebula_csrf" ? { name, value: "spent" } : undefined,
  ),
  set: vi.fn(),
};

vi.mock("next/headers", () => ({
  cookies: async () => store,
}));

vi.mock("@/lib/api/config", () => ({
  apiBaseUrl: () => "http://api.internal:8000",
  adminOrigin: () => "https://panel.example.org",
}));

const ROTATED =
  "__Host-nebula_csrf=fresh; Max-Age=28800; Path=/; SameSite=strict; Secure";

function respond(status: number, body: unknown, setCookie?: string): Response {
  const headers = new Headers({ "Content-Type": "application/json" });
  if (setCookie) {
    headers.append("set-cookie", setCookie);
  }
  return new Response(JSON.stringify(body), { status, headers });
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

describe("apiFetch", () => {
  it("hands the browser the token a refused mutation issued", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => respond(403, { detail: "step_up_required" }, ROTATED)),
    );
    const { apiFetch } = await import("@/lib/api/client");
    const { StepUpRequiredError } = await import("@/lib/api/http-error");

    await expect(
      apiFetch("/v1/admin/users/u/devices/d/revoke", { method: "POST" }),
    ).rejects.toBeInstanceOf(StepUpRequiredError);

    expect(store.set).toHaveBeenCalledWith({
      name: "__Host-nebula_csrf",
      value: "fresh",
      maxAge: 28800,
      path: "/",
      sameSite: "strict",
      secure: true,
    });
  });

  it("hands the browser the token a successful mutation issued", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => respond(200, { ok: true }, ROTATED)),
    );
    const { apiFetch } = await import("@/lib/api/client");

    await expect(apiFetch("/v1/admin/x", { method: "POST" })).resolves.toEqual({
      ok: true,
    });
    expect(store.set).toHaveBeenCalledWith(
      expect.objectContaining({ name: "__Host-nebula_csrf", value: "fresh" }),
    );
  });

  it("sends the token the browser holds", async () => {
    const fetchMock = vi.fn<typeof fetch>(async () =>
      respond(200, {}, ROTATED),
    );
    vi.stubGlobal("fetch", fetchMock);
    const { apiFetch } = await import("@/lib/api/client");

    await apiFetch("/v1/admin/x", { method: "POST" });

    const headers = fetchMock.mock.calls[0]?.[1]?.headers as Record<
      string,
      string
    >;
    expect(headers["X-CSRF-Token"]).toBe("spent");
  });

  it("sets nothing on a read, which spends no token", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => respond(200, { items: [] })),
    );
    const { apiFetch } = await import("@/lib/api/client");

    await apiFetch("/v1/admin/users");

    expect(store.set).not.toHaveBeenCalled();
  });

  it("sets nothing when a mutation's answer carries no cookie", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => respond(200, {})),
    );
    const { apiFetch } = await import("@/lib/api/client");

    await apiFetch("/v1/admin/x", { method: "POST" });

    expect(store.set).not.toHaveBeenCalled();
  });
});
