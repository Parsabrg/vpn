"use client";

export default function OverviewError({ reset }: { reset: () => void }) {
  return (
    <div className="notice" role="alert">
      <p>The overview could not be loaded.</p>
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
