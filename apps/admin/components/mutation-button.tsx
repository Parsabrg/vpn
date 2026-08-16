"use client";

import { useState, useTransition, type ReactNode } from "react";
import type { ActionResult } from "@/lib/api/action-result";
import { ConfirmDialog } from "./confirm-dialog";
import { StepUpModal } from "./step-up-modal";

interface MutationButtonProps<T> {
  triggerLabel: string;
  triggerClassName: string;
  confirmTitle: string;
  confirmLabel: string;
  confirmBody: ReactNode;
  action: () => Promise<ActionResult<T>>;
  onSuccess: (data: T) => void;
}

/**
 * Confirm dialog -> run the Server Action -> if it reports
 * step_up_required, open the step-up modal and retry the same action once
 * the admin verifies a fresh TOTP code.
 */
export function MutationButton<T>({
  triggerLabel,
  triggerClassName,
  confirmTitle,
  confirmLabel,
  confirmBody,
  action,
  onSuccess,
}: MutationButtonProps<T>) {
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  function run() {
    setError(null);
    startTransition(async () => {
      const result = await action();
      if (result.ok) {
        setConfirmOpen(false);
        onSuccess(result.data);
        return;
      }
      if (result.code === "step_up_required") {
        setConfirmOpen(false);
        setStepUpOpen(true);
        return;
      }
      setError(result.message);
    });
  }

  return (
    <>
      <button
        type="button"
        className={triggerClassName}
        onClick={() => {
          setError(null);
          setConfirmOpen(true);
        }}
      >
        {triggerLabel}
      </button>
      <ConfirmDialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        title={confirmTitle}
        confirmLabel={confirmLabel}
        pending={pending}
        error={error}
        onConfirm={run}
      >
        {confirmBody}
      </ConfirmDialog>
      <StepUpModal
        open={stepUpOpen}
        onCancel={() => {
          setStepUpOpen(false);
        }}
        onVerified={() => {
          setStepUpOpen(false);
          run();
        }}
      />
    </>
  );
}
