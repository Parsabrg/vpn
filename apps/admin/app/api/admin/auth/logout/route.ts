import type { NextRequest } from "next/server";
import { proxyAdminAuthRequest } from "@/lib/api/auth-proxy";

// Both spellings: the API prefixes them with __Host- outside development.
const SESSION_COOKIES = [
  "__Host-nebula_admin",
  "nebula_admin",
  "__Host-nebula_csrf",
  "nebula_csrf",
];

export async function POST(request: NextRequest) {
  const response = await proxyAdminAuthRequest(
    request,
    "/v1/admin/auth/logout",
  );
  // Signed out in this browser even when the API refused the request (a
  // spent CSRF token); otherwise every page kept loading and every action
  // kept failing.
  if (!response.ok) {
    for (const name of SESSION_COOKIES) {
      response.cookies.set(name, "", {
        maxAge: 0,
        path: "/",
        secure:
          name.startsWith("__Host-") || request.nextUrl.protocol === "https:",
      });
    }
  }
  return response;
}
