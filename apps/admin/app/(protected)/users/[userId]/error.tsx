"use client";

export default function UserDetailError({ reset }: { reset: () => void }) {
  return (
    <div className="notice" role="alert">
      <p>This user could not be loaded.</p>
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
