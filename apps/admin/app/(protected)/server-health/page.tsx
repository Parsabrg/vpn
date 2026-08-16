import type { Metadata } from "next";
import { listVpnServers } from "@/lib/topology";
import { DataTable } from "@/components/data-table";
import { EmptyState } from "@/components/empty-state";

export const metadata: Metadata = {
  title: "Server health",
};

export default async function ServerHealthPage() {
  const servers = await listVpnServers();

  return (
    <>
      <section className="page-heading" aria-labelledby="server-health-title">
        <h1 id="server-health-title">Server health</h1>
        <p>VPN server inventory and state.</p>
      </section>

      {servers.length === 0 ? (
        <EmptyState title="VPN server inventory" status="not-connected">
          <p>
            No VPN server has been provisioned yet. This page reads the real
            server inventory endpoint -- it is empty because Phase 1.6 has not
            provisioned any servers, not because the connection is missing. Real
            health telemetry (reachability, load) also arrives in Phase 1.6.
          </p>
        </EmptyState>
      ) : (
        <DataTable
          caption="VPN servers"
          headers={["Code", "Name", "State", "Host", "Max devices"]}
          emptyMessage="No VPN servers are configured."
          rows={servers.map((server) => ({
            key: server.id,
            cells: [
              server.code,
              server.displayName,
              server.state,
              server.publicHost,
              server.maximumDevices,
            ],
          }))}
        />
      )}
    </>
  );
}
