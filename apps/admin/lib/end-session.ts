import { readCsrfCookie } from "./csrf-client";

/**
 * Signs out and opens the sign-in page with a full load, so no page is left
 * showing buttons that can only fail. The logout route clears the cookies
 * even when the API refuses the request (a spent CSRF token).
 */
export async function endSession(reason?: "expired"): Promise<void> {
  const csrfToken = readCsrfCookie();
  try {
    await fetch("/api/admin/auth/logout", {
      method: "POST",
      headers: csrfToken ? { "X-CSRF-Token": csrfToken } : {},
      body: "{}",
    });
  } finally {
    window.location.assign(reason ? `/login?reason=${reason}` : "/login");
  }
}

/** True, after starting the sign-out, when an action found the session gone. */
export function endedSession(result: { ok: boolean; code?: string }): boolean {
  if (result.ok || result.code !== "signed_out") {
    return false;
  }
  void endSession("expired");
  return true;
}
