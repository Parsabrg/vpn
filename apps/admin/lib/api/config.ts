import "server-only";

/** The internal, container-network address of the FastAPI control plane. */
export function apiBaseUrl(): string {
  const url = process.env.NEBULA_API_INTERNAL_URL;
  if (!url) {
    throw new Error("NEBULA_API_INTERNAL_URL is not configured");
  }
  return url;
}

/**
 * This admin app's own public origin, exactly as configured in the API's
 * NEBULA_ALLOWED_ORIGINS allowlist. Server-to-server mutation calls present
 * this as their Origin header, since FastAPI's admin CSRF/origin check has
 * no browser-supplied Origin to read when the request comes from this
 * server rather than the browser directly.
 */
export function adminOrigin(): string {
  const origin = process.env.NEBULA_ADMIN_ORIGIN;
  if (!origin) {
    throw new Error("NEBULA_ADMIN_ORIGIN is not configured");
  }
  return origin;
}
