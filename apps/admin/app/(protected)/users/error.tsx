"use client";

export default function UsersError({ reset }: { reset: () => void }) {
  return (
    <div className="notice" role="alert">
      <p>Users could not be loaded.</p>
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
