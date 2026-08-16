import type { Metadata } from "next";
import { EmptyState } from "@/components/empty-state";

export const metadata: Metadata = {
  title: "Permissions",
};

export default function PermissionsPage() {
  return (
    <>
      <section className="page-heading" aria-labelledby="permissions-title">
        <h1 id="permissions-title">Permissions</h1>
        <p>Grant and review which users may reach which VPN servers.</p>
      </section>

      <EmptyState title="Permission management" status="not-implemented">
        <p>
          Permissions have no server-side API yet. Phase 1.6 introduces VPN
          server provisioning and the permission model this page will manage --
          granting permissions before servers exist would have nothing to grant
          access to.
        </p>
      </EmptyState>
    </>
  );
}
