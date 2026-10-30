"use client";

export default function RequestsError({ reset }: { reset: () => void }) {
  return (
    <div className="notice" role="alert">
      <p>Account requests could not be loaded.</p>
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
