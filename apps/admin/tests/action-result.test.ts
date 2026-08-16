import { describe, expect, it } from "vitest";
import { toActionResult } from "@/lib/api/action-result";
import { ApiError, StepUpRequiredError } from "@/lib/api/http-error";

describe("toActionResult", () => {
  it("returns ok:true with the resolved value on success", async () => {
    const result = await toActionResult(Promise.resolve({ id: "1" }));
    expect(result).toEqual({ ok: true, data: { id: "1" } });
  });

  it("maps StepUpRequiredError to step_up_required", async () => {
    const result = await toActionResult(
      Promise.reject(new StepUpRequiredError()),
    );
    expect(result).toEqual({
      ok: false,
      code: "step_up_required",
      message: "Step-up verification is required",
    });
  });

  it("maps a 403 ApiError to forbidden", async () => {
    const result = await toActionResult(
      Promise.reject(new ApiError(403, "denied", "Request denied")),
    );
    expect(result).toEqual({
      ok: false,
      code: "forbidden",
      message: "Request denied",
    });
  });

  it("maps a 429 ApiError to rate_limited", async () => {
    const result = await toActionResult(
      Promise.reject(new ApiError(429, null, "Too many requests")),
    );
    expect(result).toEqual({
      ok: false,
      code: "rate_limited",
      message: "Too many requests",
    });
  });

  it("maps a 404 ApiError to not_found", async () => {
    const result = await toActionResult(
      Promise.reject(new ApiError(404, null, "Not found")),
    );
    expect(result).toEqual({
      ok: false,
      code: "not_found",
      message: "Not found",
    });
  });

  it("maps any other error to unknown with a generic message", async () => {
    const result = await toActionResult(Promise.reject(new Error("boom")));
    expect(result).toEqual({
      ok: false,
      code: "unknown",
      message: "Something went wrong.",
    });
  });
});
