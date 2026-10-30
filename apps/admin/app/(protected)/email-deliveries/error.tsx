"use client";

export default function EmailDeliveriesError({ reset }: { reset: () => void }) {
  return (
    <div className="notice" role="alert">
      <p>Email deliveries could not be loaded.</p>
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
