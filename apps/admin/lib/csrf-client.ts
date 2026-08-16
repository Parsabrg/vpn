/** Client-safe mirror of lib/api/csrf.ts: the CSRF cookie is deliberately non-HttpOnly. */
const CSRF_COOKIE_NAMES = ["__Host-nebula_csrf", "nebula_csrf"] as const;

export function readCsrfCookie(): string | null {
  for (const name of CSRF_COOKIE_NAMES) {
    const prefix = `${name}=`;
    const cookie = document.cookie
      .split("; ")
      .find((entry) => entry.startsWith(prefix));
    if (cookie) {
      return decodeURIComponent(cookie.slice(prefix.length));
    }
  }
  return null;
}
