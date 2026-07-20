type StatusCardProps = Readonly<{
  title: string;
  status: "scaffolded" | "not-connected" | "not-implemented";
  children: React.ReactNode;
}>;

const labels: Record<StatusCardProps["status"], string> = {
  scaffolded: "Scaffolded",
  "not-connected": "Not connected",
  "not-implemented": "Not implemented",
};

export function StatusCard({ title, status, children }: StatusCardProps) {
  return (
    <article className="status-card">
      <div className="status-card__heading">
        <h2>{title}</h2>
        <span className={`status-pill status-pill--${status}`}>
          {labels[status]}
        </span>
      </div>
      <div className="status-card__body">{children}</div>
    </article>
  );
}
