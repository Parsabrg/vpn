"use client";

export default function AuditLogError({ reset }: { reset: () => void }) {
  return (
    <div className="notice" role="alert">
      <p>The audit log could not be loaded.</p>
      <button
        type="button"
        className="button button--secondary"
        onClick={reset}
      >
        Try again
      </button>
    </div>
  );
}
