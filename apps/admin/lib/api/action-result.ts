import { ApiError, StepUpRequiredError } from "./http-error";

export type ActionErrorCode =
  "forbidden" | "step_up_required" | "rate_limited" | "not_found" | "unknown";

export type ActionResult<T> =
  { ok: true; data: T } | { ok: false; code: ActionErrorCode; message: string };

/**
 * Wraps an `apiFetch` call for a Server Action. Never throws: Next.js
 * Server Action error boundaries are the wrong tool for an expected,
 * recoverable outcome like "this mutation needs step-up MFA" or "an
 * auditor tried to mutate something" -- the caller renders these inline.
 */
export async function toActionResult<T>(
  promise: Promise<T>,
): Promise<ActionResult<T>> {
  try {
    return { ok: true, data: await promise };
  } catch (error) {
    if (error instanceof StepUpRequiredError) {
      return { ok: false, code: "step_up_required", message: error.message };
    }
    if (error instanceof ApiError) {
      if (error.status === 403) {
        return { ok: false, code: "forbidden", message: error.message };
      }
      if (error.status === 429) {
        return { ok: false, code: "rate_limited", message: error.message };
      }
      if (error.status === 404) {
        return { ok: false, code: "not_found", message: error.message };
      }
    }
    return { ok: false, code: "unknown", message: "Something went wrong." };
  }
}
