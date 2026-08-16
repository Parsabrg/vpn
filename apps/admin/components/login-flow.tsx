"use client";

import { useRouter } from "next/navigation";
import { type FormEvent, useState } from "react";
import { MfaCodeInput } from "./mfa-code-input";

interface ChallengeResponseBody {
  challenge: string;
  next_step: "mfa" | "enroll";
  expires_in: number;
}

interface EnrollmentResponseBody {
  challenge: string;
  expires_in: number;
  secret: string;
  provisioning_uri: string;
}

interface SessionResponseBody {
  admin_id: string;
  role: string;
  csrf_token: string | null;
  step_up: boolean;
  recovery_codes?: string[];
}

interface ErrorResponseBody {
  detail?: string;
}

type Phase =
  | { name: "credentials" }
  | { name: "mfa"; challenge: string }
  | {
      name: "enroll";
      challenge: string;
      secret: string;
      provisioningUri: string;
    }
  | { name: "recovery-codes"; codes: string[] };

const GENERIC_ERROR = "That did not work. Please try again.";

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    let message = GENERIC_ERROR;
    try {
      const errorBody = (await response.json()) as ErrorResponseBody;
      if (typeof errorBody.detail === "string") {
        message = errorBody.detail;
      }
    } catch {
      // Non-JSON error body; keep the generic message.
    }
    throw new Error(message);
  }
  return (await response.json()) as T;
}

export function LoginFlow() {
  const router = useRouter();
  const [phase, setPhase] = useState<Phase>({ name: "credentials" });
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  function goToDashboard() {
    router.push("/");
    router.refresh();
  }

  async function handleCredentials(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setPending(true);
    const form = new FormData(event.currentTarget);
    try {
      const body = await postJson<ChallengeResponseBody>(
        "/api/admin/auth/login",
        {
          identifier: form.get("identifier"),
          password: form.get("password"),
        },
      );
      if (body.next_step === "enroll") {
        const enrollment = await postJson<EnrollmentResponseBody>(
          "/api/admin/auth/mfa/enrollment",
          { challenge: body.challenge },
        );
        setPhase({
          name: "enroll",
          challenge: enrollment.challenge,
          secret: enrollment.secret,
          provisioningUri: enrollment.provisioning_uri,
        });
      } else {
        setPhase({ name: "mfa", challenge: body.challenge });
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : GENERIC_ERROR);
    } finally {
      setPending(false);
    }
  }

  async function handleMfaVerify(
    event: FormEvent<HTMLFormElement>,
    challenge: string,
  ) {
    event.preventDefault();
    setError(null);
    setPending(true);
    const form = new FormData(event.currentTarget);
    try {
      await postJson<SessionResponseBody>("/api/admin/auth/mfa/verify", {
        challenge,
        code: form.get("code"),
        method: "totp",
      });
      goToDashboard();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : GENERIC_ERROR);
    } finally {
      setPending(false);
    }
  }

  async function handleEnrollConfirm(
    event: FormEvent<HTMLFormElement>,
    challenge: string,
  ) {
    event.preventDefault();
    setError(null);
    setPending(true);
    const form = new FormData(event.currentTarget);
    try {
      const body = await postJson<SessionResponseBody>(
        "/api/admin/auth/mfa/enrollment/confirm",
        {
          challenge,
          code: form.get("code"),
        },
      );
      setPhase({ name: "recovery-codes", codes: body.recovery_codes ?? [] });
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : GENERIC_ERROR);
    } finally {
      setPending(false);
    }
  }

  if (phase.name === "credentials") {
    return (
      <form className="auth-form" onSubmit={handleCredentials} noValidate>
        <div className="field">
          <label htmlFor="identifier" className="field__label">
            Email or username
          </label>
          <input
            id="identifier"
            name="identifier"
            type="text"
            autoComplete="username"
            required

            autoFocus
          />
        </div>
        <div className="field">
          <label htmlFor="password" className="field__label">
            Password
          </label>
          <input
            id="password"
            name="password"
            type="password"
            autoComplete="current-password"
            required
          />
        </div>
        {error ? (
          <p role="alert" className="field__error">
            {error}
          </p>
        ) : null}
        <button
          type="submit"
          className="button button--primary"
          disabled={pending}
        >
          {pending ? "Signing in…" : "Continue"}
        </button>
      </form>
    );
  }

  if (phase.name === "mfa") {
    return (
      <form
        className="auth-form"
        onSubmit={(event) => {
          void handleMfaVerify(event, phase.challenge);
        }}
        noValidate
      >
        <p>Enter the 6-digit code from your authenticator app.</p>
        <MfaCodeInput id="code" label="Authentication code" autoFocus />
        {error ? (
          <p role="alert" className="field__error">
            {error}
          </p>
        ) : null}
        <button
          type="submit"
          className="button button--primary"
          disabled={pending}
        >
          {pending ? "Verifying…" : "Verify"}
        </button>
      </form>
    );
  }

  if (phase.name === "enroll") {
    return (
      <div className="auth-form">
        <p>
          Set up an authenticator app with this key, then enter the 6-digit code
          it shows.
        </p>
        <p className="mfa-secret" aria-label="Setup key">
          {phase.secret}
        </p>
        <form
          onSubmit={(event) => {
            void handleEnrollConfirm(event, phase.challenge);
          }}
          noValidate
        >
          <MfaCodeInput id="code" label="Authentication code" autoFocus />
          {error ? (
            <p role="alert" className="field__error">
              {error}
            </p>
          ) : null}
          <button
            type="submit"
            className="button button--primary"
            disabled={pending}
          >
            {pending ? "Confirming…" : "Confirm"}
          </button>
        </form>
      </div>
    );
  }

  return (
    <div className="auth-form">
      <p role="status">
        Save these single-use recovery codes now. They will not be shown again.
      </p>
      <ul className="recovery-codes">
        {phase.codes.map((code) => (
          <li key={code}>{code}</li>
        ))}
      </ul>
      <button
        type="button"
        className="button button--primary"
        onClick={goToDashboard}
      >
        Continue to dashboard
      </button>
    </div>
  );
}
