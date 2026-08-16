import { listPendingAccountRequests } from "@/lib/account-requests";
import { listVpnServers } from "@/lib/topology";
import { listUsers } from "@/lib/users";
import { StatTile } from "@/components/stat-tile";

export default async function OverviewPage() {
  const [pendingRequests, totalUsers, activeUsers, servers] = await Promise.all(
    [
      listPendingAccountRequests(),
      listUsers({ limit: 1 }),
      listUsers({ state: "active", limit: 1 }),
      listVpnServers(),
    ],
  );

  return (
    <>
      <section className="page-heading" aria-labelledby="overview-title">
        <h1 id="overview-title">Overview</h1>
        <p>Current state of account requests, users, and VPN capacity.</p>
      </section>

      <section className="status-grid" aria-label="Administration summary">
        <StatTile
          label="Pending requests"
          value={pendingRequests.length}
          href="/requests"
        />
        <StatTile
          label="Active users"
          value={activeUsers.total}
          href="/users"
        />
        <StatTile label="Total users" value={totalUsers.total} href="/users" />
        <StatTile
          label="VPN servers"
          value={servers.length}
          href="/server-health"
        />
      </section>
    </>
  );
}
