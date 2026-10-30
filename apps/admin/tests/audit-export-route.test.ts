import { afterEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

vi.mock("@/lib/api/config", () => ({
  apiBaseUrl: () => "http://api.internal:8000",
  adminOrigin: () => "https://panel.example.org",
}));

import { GET } from "@/app/api/admin/audit-log/export/route";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("audit log export download", () => {
  it("relays the chain with the session cookie and keeps the file name", async () => {
    const fetchMock = vi.fn(
      async () =>
        new Response('{"format":"nebula-audit-chain/1"}\n', {
          status: 200,
          headers: {
            "Content-Type": "application/x-ndjson",
            "Content-Disposition":
              'attachment; filename="nebula-audit-x.jsonl"',
          },
        }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const request = new NextRequest(
      "https://panel.example.org/api/admin/audit-log/export",
      {
        headers: { cookie: "__Host-nebula_admin=session" },
      },
    );

    const response = await GET(request);

    expect(response.status).toBe(200);
    expect(response.headers.get("content-disposition")).toContain(
      "nebula-audit-x.jsonl",
    );
    expect(await response.text()).toContain("nebula-audit-chain/1");
    const [url, init] = fetchMock.mock.calls[0] as unknown as [
      URL,
      RequestInit,
    ];
    expect(String(url)).toBe(
      "http://api.internal:8000/v1/admin/audit-log/export",
    );
    expect((init.headers as Record<string, string>).Cookie).toBe(
      "__Host-nebula_admin=session",
    );
  });

  it("passes a refusal through without offering a file", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response('{"detail":"no"}', { status: 401 })),
    );

    const response = await GET(
      new NextRequest("https://panel.example.org/api/admin/audit-log/export"),
    );

    expect(response.status).toBe(401);
    expect(response.headers.get("content-disposition")).toBeNull();
  });
});
