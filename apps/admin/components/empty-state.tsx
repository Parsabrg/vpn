import type { ReactNode } from "react";

interface EmptyStateProps {
  title: string;
  status: "not-connected" | "not-implemented";
  children: ReactNode;
}

const labels: Record<EmptyStateProps["status"], string> = {
  "not-connected": "Not connected",
  "not-implemented": "Not implemented",
};

/** A full-width, honest explanation for a page with nothing behind it yet. */
export function EmptyState({ title, status, children }: EmptyStateProps) {
  return (
    <section className="empty-state" aria-labelledby="empty-state-title">
      <div className="empty-state__heading">
        <h2 id="empty-state-title">{title}</h2>
        <span className={`status-pill status-pill--${status}`}>
          {labels[status]}
        </span>
      </div>
      <div className="empty-state__body">{children}</div>
    </section>
  );
}
