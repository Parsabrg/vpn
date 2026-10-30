"use client";

import { useState } from "react";
import { readCsrfCookie } from "@/lib/csrf-client";
import { RecoveryCodeActions } from "./login-flow";

/**
 * New single-use recovery codes, replacing the old ones. There was no way to
 * do this from the panel: codes that leaked (a screenshot, 2026-10-29) stayed
 * valid with nothing an admin could do about it.
 */
export function RecoveryCodesRotate() {
  const [codes, setCodes] = useState<string[] | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function rotate() {
    setPending(true);
    setError(null);
    const headers: HeadersInit = { "Content-Type": "application/json" };
    const csrfToken = readCsrfCookie();
    if (csrfToken) {
      headers["X-CSRF-Token"] = csrfToken;
    }
    try {
      const response = await fetch("/api/admin/auth/recovery-codes/rotate", {
        method: "POST",
        headers,
        body: "{}",
      });
      if (!response.ok) {
        setError(
          response.status === 403
            ? "Sign in again with your authenticator code, then try again."
            : "The codes could not be replaced. Try again.",
        );
        return;
      }
      const body = (await response.json()) as { recovery_codes: string[] };
      setCodes(body.recovery_codes);
      setConfirming(false);
    } finally {
      setPending(false);
    }
  }

  if (codes) {
    return (
      <div>
        <p role="status">
          Your old recovery codes no longer work. Save these now; they will not
          be shown again.
        </p>
        <ol className="recovery-codes" aria-label="Recovery codes">
          {codes.map((code) => (
            <li key={code}>{code}</li>
          ))}
        </ol>
        <RecoveryCodeActions codes={codes} />
      </div>
    );
  }

  return (
    <div>
      <p>
        Each code signs you in once if you lose your authenticator. Replace them
        if they may have been seen by someone else.
      </p>
      {confirming ? (
        <div className="readiness__actions">
          <button
            type="button"
            className="button button--primary"
            disabled={pending}
            onClick={rotate}
          >
            {pending ? "Replacing…" : "Replace my codes"}
          </button>
          <button
            type="button"
            className="button"
            disabled={pending}
            onClick={() => setConfirming(false)}
          >
            Cancel
          </button>
        </div>
      ) : (
        <button
          type="button"
          className="button"
          onClick={() => setConfirming(true)}
        >
          Generate new recovery codes
        </button>
      )}
      {error ? <p role="alert">{error}</p> : null}
    </div>
  );
}
