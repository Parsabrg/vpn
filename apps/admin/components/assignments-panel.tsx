"use client";

import { useState } from "react";
import { assignServer, revokeAssignment } from "@/lib/access-actions";
import type { UserAssignmentListItem } from "@/lib/access";
import type { VpnServerListItem } from "@/lib/topology";
import { MutationButton } from "./mutation-button";

function upsertById<T extends { id: string }>(items: T[], item: T): T[] {
  const index = items.findIndex((current) => current.id === item.id);
  if (index === -1) {
    return [item, ...items];
  }
  const next = [...items];
  next[index] = item;
  return next;
}

export function AssignmentsPanel({
  userId,
  initialAssignments,
  servers,
}: {
  userId: string;
  initialAssignments: UserAssignmentListItem[];
  servers: VpnServerListItem[];
}) {
  const [assignments, setAssignments] = useState(initialAssignments);
  const [selectedServerId, setSelectedServerId] = useState("");

  const assignedServerIds = new Set(
    assignments
      .filter((assignment) => assignment.state === "active")
      .map((assignment) => assignment.vpnServerId),
  );
  const assignableServers = servers.filter(
    (server) => !assignedServerIds.has(server.id),
  );
  const effectiveSelection = assignableServers.some(
    (server) => server.id === selectedServerId,
  )
    ? selectedServerId
    : (assignableServers[0]?.id ?? "");

  return (
    <>
      {assignments.length === 0 ? (
        <p role="status">This user has no server assignments.</p>
      ) : (
        <table className="data-table" aria-label="Assignments">
          <thead>
            <tr>
              <th scope="col">Server</th>
              <th scope="col">State</th>
              <th scope="col">Assigned</th>
              <th scope="col">Actions</th>
            </tr>
          </thead>
          <tbody>
            {assignments.map((assignment) => (
              <tr key={assignment.id}>
                <td>{assignment.serverDisplayName}</td>
                <td>
                  <span className={`badge badge--${assignment.state}`}>
                    {assignment.state}
                  </span>
                </td>
                <td>{new Date(assignment.assignedAt).toLocaleString()}</td>
                <td>
                  {assignment.state === "active" ? (
                    <MutationButton
                      triggerLabel="Revoke"
                      triggerClassName="button button--danger"
                      confirmTitle={`Revoke ${assignment.serverDisplayName}`}
                      confirmLabel="Revoke"
                      confirmBody={
                        <p>This user will lose access to this VPN server.</p>
                      }
                      action={() =>
                        revokeAssignment(userId, assignment.vpnServerId)
                      }
                      onSuccess={(updated) =>
                        setAssignments((current) =>
                          upsertById(current, updated),
                        )
                      }
                    />
                  ) : (
                    "—"
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {assignableServers.length > 0 ? (
        <MutationButton
          triggerLabel="Assign server"
          triggerClassName="button button--primary"
          confirmTitle="Assign VPN server"
          confirmLabel="Assign"
          confirmBody={
            <div className="field">
              <label htmlFor="assign-server-select" className="field__label">
                Server
              </label>
              <select
                id="assign-server-select"
                value={effectiveSelection}
                onChange={(event) => setSelectedServerId(event.target.value)}
              >
                {assignableServers.map((server) => (
                  <option key={server.id} value={server.id}>
                    {server.displayName}
                  </option>
                ))}
              </select>
            </div>
          }
          action={() => assignServer(userId, effectiveSelection)}
          onSuccess={(assigned) =>
            setAssignments((current) => upsertById(current, assigned))
          }
        />
      ) : null}
    </>
  );
}
