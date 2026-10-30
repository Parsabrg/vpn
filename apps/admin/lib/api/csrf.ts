import "server-only";
import { cookies } from "next/headers";

/** FastAPI names this cookie by env: __Host- prefixed in staging/production. */
const CSRF_COOKIE_NAMES = ["__Host-nebula_csrf", "nebula_csrf"] as const;

export async function readCsrfToken(): Promise<string | null> {
  const store = await cookies();
  for (const name of CSRF_COOKIE_NAMES) {
    const cookie = store.get(name);
    if (cookie) {
      return cookie.value;
    }
  }
  return null;
}
