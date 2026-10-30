/** A non-2xx response from the API, with the generic detail string it returned. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string | null;

  constructor(status: number, code: string | null, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

/** A mutation was rejected specifically because the admin session needs step-up MFA. */
export class StepUpRequiredError extends ApiError {
  constructor() {
    super(403, "step_up_required", "Step-up verification is required");
    this.name = "StepUpRequiredError";
  }
}
