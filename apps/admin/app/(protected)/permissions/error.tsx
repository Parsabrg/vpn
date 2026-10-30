"use client";

export default function PermissionsError({ reset }: { reset: () => void }) {
  return (
    <div className="notice" role="alert">
      <p>Permissions could not be loaded.</p>
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
