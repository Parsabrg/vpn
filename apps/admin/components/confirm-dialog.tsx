"use client";

import { useEffect, useRef, type ReactNode } from "react";

interface ConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  confirmLabel: string;
  pending: boolean;
  error: string | null;
  onConfirm: () => void;
  children?: ReactNode;
}

/**
 * Wraps a native <dialog> as a controlled component: React owns `open`,
 * an effect drives showModal()/close(), and the dialog's own `cancel`/`close`
 * events (fired on Escape, among other things) sync back into `open`.
 */
export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  confirmLabel,
  pending,
  error,
  onConfirm,
  children,
}: ConfirmDialogProps) {
  const dialogRef = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) {
      return;
    }
    if (open && !dialog.open) {
      dialog.showModal();
    } else if (!open && dialog.open) {
      dialog.close();
    }
  }, [open]);

  return (
    <dialog
      ref={dialogRef}
      className="dialog"
      onClose={() => {
        onOpenChange(false);
      }}
      onCancel={() => {
        onOpenChange(false);
      }}
    >
      <form
        className="dialog__form"
        onSubmit={(event) => {
          event.preventDefault();
          onConfirm();
        }}
      >
        <h2>{title}</h2>
        {children}
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
            onClick={() => {
              onOpenChange(false);
            }}
          >
            Cancel
          </button>
          <button
            type="submit"
            className="button button--primary"
            disabled={pending}
          >
            {pending ? "Working…" : confirmLabel}
          </button>
        </div>
      </form>
    </dialog>
  );
}
