import "server-only";
import { cookies } from "next/headers";
import { adminOrigin, apiBaseUrl } from "./config";
import { readCsrfToken } from "./csrf";
import { ApiError, StepUpRequiredError } from "./http-error";
import { parseSetCookie } from "./set-cookie";

const GENERIC_DETAIL = "Request was not accepted";

interface ApiRequestOptions {
  method?: "GET" | "POST";
  // An object: apiFetch encodes it. A pre-encoded string reached the API as a
  // JSON string and was refused (422).
  body?: object;
  searchParams?: Record<string, string | number | boolean | undefined>;
}

/**
 * Relays the browser's whole Cookie header rather than reading one named
 * cookie: FastAPI's admin cookie name depends on its own `env` setting
 * (`nebula_admin` vs `__Host-nebula_admin`), and HttpOnly only blocks
 * browser JS, not this server process, from reading it.
 */
async function forwardedCookieHeader(): Promise<string> {
  const store = await cookies();
  return store
    .getAll()
    .map((cookie) => `${cookie.name}=${cookie.value}`)
    .join("; ");
}

function extractDetail(body: unknown): string | null {
  if (body !== null && typeof body === "object" && "detail" in body) {
    const detail = (body as { detail: unknown }).detail;
    if (typeof detail === "string") {
      return detail;
    }
  }
  return null;
}

/**
 * Hands the browser the cookies the API set on a mutation.
 *
 * Every admin mutation spends the CSRF token and issues the next one -- a
 * mutation refused with step_up_required included. This request comes from
 * the admin server, so the replacement arrives here rather than in the
 * browser. Dropped, the browser goes on sending the spent token, and its next
 * request is refused as "Authentication was not accepted": most visibly the
 * step-up verification itself, which then rejected every correct code.
 */
async function relaySetCookies(response: Response): Promise<void> {
  const headers = response.headers.getSetCookie();
  if (headers.length === 0) {
    return;
  }
  const store = await cookies();
  for (const header of headers) {
    const cookie = parseSetCookie(header);
    if (cookie) {
      store.set(cookie);
    }
  }
}

/**
 * Server-only fetch against the internal FastAPI origin. GETs relay the
 * session cookie only; POSTs additionally send the CSRF header and an
 * Origin header matching this app's own public origin, since FastAPI's
 * admin CSRF/origin check has no browser-supplied Origin to read when the
 * request comes from this server rather than the browser directly.
 */
export async function apiFetch<T>(
  path: string,
  options: ApiRequestOptions = {},
): Promise<T> {
  const method = options.method ?? "GET";
  const url = new URL(path, apiBaseUrl());
  if (options.searchParams) {
    for (const [key, value] of Object.entries(options.searchParams)) {
      if (value !== undefined) {
        url.searchParams.set(key, String(value));
      }
    }
  }

  const headers: Record<string, string> = {
    Cookie: await forwardedCookieHeader(),
  };
  const init: RequestInit = { method, headers, cache: "no-store" };

  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(options.body);
  } else if (method === "POST") {
    headers["Content-Type"] = "application/json";
    init.body = "{}";
  }

  if (method === "POST") {
    headers.Origin = adminOrigin();
    const csrf = await readCsrfToken();
    if (csrf) {
      headers["X-CSRF-Token"] = csrf;
    }
  }

  const response = await fetch(url, init);
  if (method === "POST") {
    // Before any error is thrown: a refused mutation rotates the token too.
    await relaySetCookies(response);
  }

  if (!response.ok) {
    let detail: string | null = null;
    try {
      detail = extractDetail(await response.json());
    } catch {
      // Non-JSON error body; fall through to the generic message.
    }
    if (response.status === 403 && detail === "step_up_required") {
      throw new StepUpRequiredError();
    }
    throw new ApiError(response.status, detail, detail ?? GENERIC_DETAIL);
  }

  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}
