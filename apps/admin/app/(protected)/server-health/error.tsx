"use client";

export default function ServerHealthError({ reset }: { reset: () => void }) {
  return (
    <div className="notice" role="alert">
      <p>Server health could not be loaded.</p>
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
