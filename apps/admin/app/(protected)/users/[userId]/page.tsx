import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { getUserDetail } from "@/lib/users";
import { listUserAssignments, listUserPermissions } from "@/lib/access";
import { listProtocolProfiles, listVpnServers } from "@/lib/topology";
import { UserStatusControl } from "@/components/user-status-control";
import { DeviceRow } from "@/components/device-row";
import { SessionRow } from "@/components/session-row";
import { PermissionsPanel } from "@/components/permissions-panel";
import { AssignmentsPanel } from "@/components/assignments-panel";
import { AccessReadiness } from "@/components/access-readiness";
import { DeviceLimitControl } from "@/components/device-limit-control";
import { DnsProfileControl } from "@/components/dns-profile-control";
import { ExpiryControl } from "@/components/expiry-control";
import { TrafficAllowancePanel } from "@/components/traffic-allowance-panel";

export const metadata: Metadata = {
  title: "User detail",
};

export default async function UserDetailPage({
  params,
}: {
  params: Promise<{ userId: string }>;
}) {
  const { userId } = await params;
  const detail = await getUserDetail(userId);
  if (!detail) {
    notFound();
  }
  const { user, devices, sessions, traffic } = detail;
  const [permissions, assignments, profiles, servers] = await Promise.all([
    listUserPermissions(user.id),
    listUserAssignments(user.id),
    listProtocolProfiles(),
    listVpnServers(),
  ]);

  const grantedProfileIds = new Set(
    permissions
      .filter((p) => p.state === "enabled")
      .map((p) => p.protocolProfileId),
  );
  const assignedServerIds = new Set(
    assignments.filter((a) => a.state === "active").map((a) => a.vpnServerId),
  );

  return (
    <>
      <section className="page-heading" aria-labelledby="user-detail-title">
        <h1 id="user-detail-title">{user.email}</h1>
        <p>{user.username ?? "No username set"}</p>
        <UserStatusControl userId={user.id} initialState={user.state} />
      </section>

      <AccessReadiness
        userId={user.id}
        hasProtocol={grantedProfileIds.size > 0}
        hasServer={assignedServerIds.size > 0}
        missingProfileIds={profiles
          .filter((profile) => !grantedProfileIds.has(profile.id))
          .map((profile) => profile.id)}
        missingServerIds={servers
          .filter(
            (server) =>
              server.state === "active" && !assignedServerIds.has(server.id),
          )
          .map((server) => server.id)}
      />

      <dl className="detail-grid">
        <div>
          <dt>Device limit</dt>
          <dd>
            <DeviceLimitControl
              userId={user.id}
              initialLimit={user.deviceLimit}
            />
          </dd>
        </div>
        <div>
          <dt>DNS</dt>
          <dd>
            <DnsProfileControl
              userId={user.id}
              initialProfile={user.dnsProfile}
            />
          </dd>
        </div>
        <div>
          <dt>Created</dt>
          <dd>{new Date(user.createdAt).toLocaleString()}</dd>
        </div>
        <div>
          <dt>Activated</dt>
          <dd>
            {user.activatedAt
              ? new Date(user.activatedAt).toLocaleString()
              : "—"}
          </dd>
        </div>
        <div>
          <dt>Expires</dt>
          <dd>
            <ExpiryControl userId={user.id} initialExpiresAt={user.expiresAt} />
          </dd>
        </div>
        <div>
          <dt>Disabled</dt>
          <dd>
            {user.disabledAt ? new Date(user.disabledAt).toLocaleString() : "—"}
          </dd>
        </div>
      </dl>

      <section aria-labelledby="devices-title">
        <h2 id="devices-title">Devices</h2>
        {devices.length === 0 ? (
          <p role="status">This user has no devices.</p>
        ) : (
          <table className="data-table" aria-label="Devices">
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Platform</th>
                <th scope="col">Client version</th>
                <th scope="col">State</th>
                <th scope="col">Online</th>
                <th scope="col">DNS</th>
                <th scope="col">Actions</th>
              </tr>
            </thead>
            <tbody>
              {devices.map((device) => (
                <DeviceRow key={device.id} userId={user.id} device={device} />
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section aria-labelledby="sessions-title">
        <h2 id="sessions-title">Sessions</h2>
        {sessions.length === 0 ? (
          <p role="status">This user has no sessions.</p>
        ) : (
          <table className="data-table" aria-label="Sessions">
            <thead>
              <tr>
                <th scope="col">Device</th>
                <th scope="col">State</th>
                <th scope="col">Expires</th>
                <th scope="col">Last seen</th>
                <th scope="col">Actions</th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((session) => (
                <SessionRow
                  key={session.id}
                  userId={user.id}
                  session={session}
                />
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section aria-labelledby="traffic-title">
        <h2 id="traffic-title">Traffic allowance</h2>
        <TrafficAllowancePanel userId={user.id} initialAllowance={traffic} />
      </section>

      <section aria-labelledby="permissions-title">
        <h2 id="permissions-title">Permissions</h2>
        <PermissionsPanel
          key={`p${grantedProfileIds.size}`}
          userId={user.id}
          initialPermissions={permissions}
          profiles={profiles}
        />
      </section>

      <section aria-labelledby="assignments-title">
        <h2 id="assignments-title">Assignments</h2>
        <AssignmentsPanel
          key={`a${assignedServerIds.size}`}
          userId={user.id}
          initialAssignments={assignments}
          servers={servers}
        />
      </section>
    </>
  );
}
