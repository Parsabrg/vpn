import type { Metadata } from "next";
import { EmptyState } from "@/components/empty-state";

export const metadata: Metadata = {
  title: "Assignments",
};

export default function AssignmentsPage() {
  return (
    <>
      <section className="page-heading" aria-labelledby="assignments-title">
        <h1 id="assignments-title">Assignments</h1>
        <p>Assign devices and users to specific VPN servers.</p>
      </section>

      <EmptyState title="Assignment management" status="not-implemented">
        <p>
          Assignments have no server-side API yet. Phase 1.6 introduces VPN
          server provisioning and capacity tracking this page will assign
          devices against -- there is nothing to assign devices to until then.
        </p>
      </EmptyState>
    </>
  );
}
