import type { Metadata } from "next";
import { DataTable } from "@/components/data-table";
import { RecoveryCodesRotate } from "@/components/recovery-codes-rotate";
import { getSecurityStatus, type CheckStatus } from "@/lib/security";

export const metadata: Metadata = {
  title: "Security",
};

const STATUS_LABEL: Record<CheckStatus, string> = {
  ok: "OK",
  warning: "Warning",
  failing: "Failing",
  unknown: "Unknown",
};

export default async function SecurityPage() {
  const checks = await getSecurityStatus();
  const attention = checks.filter(
    (check) => check.status === "failing" || check.status === "warning",
  ).length;

  return (
    <>
      <section className="page-heading" aria-labelledby="security-title">
        <h1 id="security-title">Security</h1>
        <p>
          What the control plane can observe for itself, read when this page
          loaded. Anything it cannot observe says Unknown, never OK. CI scan
          results are on GitHub and are not repeated here.
        </p>
        <p role="status">
          {attention === 0
            ? "Nothing needs attention."
            : `${attention} ${attention === 1 ? "item needs" : "items need"} attention.`}
        </p>
      </section>

      <DataTable
        caption="Security checks"
        headers={["Check", "Status", "Detail", "Evidence (UTC)"]}
        emptyMessage="No checks were returned."
        rows={checks.map((check) => ({
          key: check.key,
          cells: [
            check.label,
            <span key="status" className={`badge badge--check-${check.status}`}>
              {STATUS_LABEL[check.status]}
            </span>,
            check.detail,
            check.observedAt
              ? new Date(check.observedAt)
                  .toISOString()
                  .replace("T", " ")
                  .slice(0, 19)
              : "—",
          ],
        }))}
      />

      <section className="status-card" aria-labelledby="recovery-title">
        <h2 id="recovery-title">Your recovery codes</h2>
        <RecoveryCodesRotate />
      </section>
    </>
  );
}
