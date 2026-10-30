import "server-only";
import { type NextRequest, NextResponse } from "next/server";
import { adminOrigin, apiBaseUrl } from "./config";

/**
 * Thin 1:1 proxy for one `/v1/admin/auth/*` endpoint: forwards the request
 * body and the browser's Cookie/X-CSRF-Token headers, presents this app's
 * own origin (FastAPI's origin check has no browser-supplied Origin to read
 * from a server-to-server call), and relays every Set-Cookie and the
 * X-CSRF-Token response header back verbatim. This is the only place the
 * admin app sets/clears the session cookie the browser can see -- reads
 * elsewhere stay server-only via `lib/auth/session.ts`.
 */
export async function proxyAdminAuthRequest(
  request: NextRequest,
  backendPath: string,
): Promise<NextResponse> {
  const cookieHeader = request.headers.get("cookie") ?? "";
  const csrfHeader = request.headers.get("x-csrf-token");
  const bodyText = await request.text();

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Cookie: cookieHeader,
    Origin: adminOrigin(),
  };
  if (csrfHeader) {
    headers["X-CSRF-Token"] = csrfHeader;
  }

  const upstream = await fetch(new URL(backendPath, apiBaseUrl()), {
    method: "POST",
    headers,
    body: bodyText.length > 0 ? bodyText : "{}",
    cache: "no-store",
  });

  const responseBody = await upstream.text();
  const response = new NextResponse(
    responseBody.length > 0 ? responseBody : null,
    {
      status: upstream.status,
      headers: {
        "Content-Type":
          upstream.headers.get("content-type") ?? "application/json",
      },
    },
  );

  for (const cookie of upstream.headers.getSetCookie()) {
    response.headers.append("set-cookie", cookie);
  }
  const csrfToken = upstream.headers.get("x-csrf-token");
  if (csrfToken) {
    response.headers.set("x-csrf-token", csrfToken);
  }

  return response;
}
