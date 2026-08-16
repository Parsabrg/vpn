import "server-only";
import { cookies } from "next/headers";
import { adminOrigin, apiBaseUrl } from "./config";
import { readCsrfToken } from "./csrf";
import { ApiError, StepUpRequiredError } from "./http-error";

const GENERIC_DETAIL = "Request was not accepted";

interface ApiRequestOptions {
  method?: "GET" | "POST";
  body?: unknown;
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
