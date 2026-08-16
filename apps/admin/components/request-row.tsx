"use client";

import { useState, useTransition } from "react";
import {
  approveAccountRequest,
  rejectAccountRequest,
} from "@/lib/account-requests-actions";
import type { AccountRequestListItem } from "@/lib/account-requests";
import { ConfirmDialog } from "./confirm-dialog";

export function RequestRow({ request }: { request: AccountRequestListItem }) {
  const [approveOpen, setApproveOpen] = useState(false);
  const [rejectOpen, setRejectOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [decision, setDecision] = useState<"approved" | "rejected" | null>(
    null,
  );
  const [pending, startTransition] = useTransition();

  function openApprove() {
    setError(null);
    setApproveOpen(true);
  }

  function openReject() {
    setError(null);
    setRejectOpen(true);
  }

  function handleApprove() {
    startTransition(async () => {
      const result = await approveAccountRequest(request.id);
      if (result.ok) {
        setApproveOpen(false);
        setDecision("approved");
      } else {
        setError(result.message);
      }
    });
  }

  function handleReject() {
    startTransition(async () => {
      const result = await rejectAccountRequest(
        request.id,
        reason.trim() || null,
      );
      if (result.ok) {
        setRejectOpen(false);
        setDecision("rejected");
      } else {
        setError(result.message);
      }
    });
  }

  const requestedAt = new Date(request.createdAt).toLocaleString();

  if (decision) {
    return (
      <tr>
        <td>{request.email}</td>
        <td>{request.username ?? "—"}</td>
        <td>{requestedAt}</td>
        <td>
          <span className={`badge badge--${decision}`}>{decision}</span>
        </td>
      </tr>
    );
  }

  return (
    <tr>
      <td>{request.email}</td>
      <td>{request.username ?? "—"}</td>
      <td>{requestedAt}</td>
      <td className="data-table__actions">
        <button
          type="button"
          className="button button--primary"
          onClick={openApprove}
        >
          Approve
        </button>
        <button
          type="button"
          className="button button--danger"
          onClick={openReject}
        >
          Reject
        </button>
        <ConfirmDialog
          open={approveOpen}
          onOpenChange={setApproveOpen}
          title={`Approve ${request.email}`}
          confirmLabel="Approve"
          pending={pending}
          error={error}
          onConfirm={handleApprove}
        >
          <p>This sends an activation email to {request.email}.</p>
        </ConfirmDialog>
        <ConfirmDialog
          open={rejectOpen}
          onOpenChange={setRejectOpen}
          title={`Reject ${request.email}`}
          confirmLabel="Reject"
          pending={pending}
          error={error}
          onConfirm={handleReject}
        >
          <div className="field">
            <label
              htmlFor={`reject-reason-${request.id}`}
              className="field__label"
            >
              Reason (optional)
            </label>
            <textarea
              id={`reject-reason-${request.id}`}
              value={reason}
              onChange={(event) => {
                setReason(event.target.value);
              }}
            />
          </div>
        </ConfirmDialog>
      </td>
    </tr>
  );
}
