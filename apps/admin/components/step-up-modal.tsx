"use client";

import { useEffect, useRef, useState, type FormEvent } from "react";
import { readCsrfCookie } from "@/lib/csrf-client";
import { MfaCodeInput } from "./mfa-code-input";

interface StepUpModalProps {
  open: boolean;
  onCancel: () => void;
  onVerified: () => void;
}

/**
 * Verifies a fresh TOTP code against /v1/admin/auth/step-up, which rotates
 * the session and CSRF cookies to a stepped-up session on success. The
 * caller retries the mutation that originally reported step_up_required
 * once onVerified fires -- the retry now carries the stepped-up cookie.
 */
export function StepUpModal({ open, onCancel, onVerified }: StepUpModalProps) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) {
      return;
    }
    if (open && !dialog.open) {
      setError(null);
      dialog.showModal();
    } else if (!open && dialog.open) {
      dialog.close();
    }
  }, [open]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setPending(true);
    const form = new FormData(event.currentTarget);
    const csrfToken = readCsrfCookie();
    const headers: HeadersInit = { "Content-Type": "application/json" };
    if (csrfToken) {
      headers["X-CSRF-Token"] = csrfToken;
    }
    try {
      const response = await fetch("/api/admin/auth/step-up", {
        method: "POST",
        headers,
        body: JSON.stringify({ code: form.get("code"), method: "totp" }),
      });
      if (!response.ok) {
        setError("That code was not accepted.");
        return;
      }
      onVerified();
    } finally {
      setPending(false);
    }
  }

  return (
    <dialog
      ref={dialogRef}
      className="dialog"
      onClose={onCancel}
      onCancel={onCancel}
    >
      <form
        className="dialog__form"
        onSubmit={(event) => {
          void handleSubmit(event);
        }}
        noValidate
      >
        <h2>Step-up verification required</h2>
        <p>
          Enter a fresh 6-digit code from your authenticator app to continue.
        </p>
        <MfaCodeInput id="code" label="Authentication code" autoFocus />
        {error ? (
          <p role="alert" className="field__error">
            {error}
          </p>
        ) : null}
        <div className="dialog__actions">
          <button
            type="button"
            className="button button--ghost"
            disabled={pending}
            onClick={onCancel}
          >
            Cancel
          </button>
          <button
            type="submit"
            className="button button--primary"
            disabled={pending}
          >
            {pending ? "Verifying…" : "Verify"}
          </button>
        </div>
      </form>
    </dialog>
  );
}
