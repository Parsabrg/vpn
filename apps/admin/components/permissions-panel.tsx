"use client";

import { useState } from "react";
import { grantPermission, revokePermission } from "@/lib/access-actions";
import type { UserPermissionListItem } from "@/lib/access";
import type { ProtocolProfileListItem } from "@/lib/topology";
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

export function PermissionsPanel({
  userId,
  initialPermissions,
  profiles,
}: {
  userId: string;
  initialPermissions: UserPermissionListItem[];
  profiles: ProtocolProfileListItem[];
}) {
  const [permissions, setPermissions] = useState(initialPermissions);
  const [selectedProfileId, setSelectedProfileId] = useState("");

  const grantedProfileIds = new Set(
    permissions
      .filter((permission) => permission.state === "enabled")
      .map((permission) => permission.protocolProfileId),
  );
  const grantableProfiles = profiles.filter(
    (profile) => !grantedProfileIds.has(profile.id),
  );
  const effectiveSelection = grantableProfiles.some(
    (profile) => profile.id === selectedProfileId,
  )
    ? selectedProfileId
    : (grantableProfiles[0]?.id ?? "");

  return (
    <>
      {permissions.length === 0 ? (
        <p role="status">This user has no protocol permissions.</p>
      ) : (
        <table className="data-table" aria-label="Permissions">
          <thead>
            <tr>
              <th scope="col">Profile</th>
              <th scope="col">State</th>
              <th scope="col">Granted</th>
              <th scope="col">Actions</th>
            </tr>
          </thead>
          <tbody>
            {permissions.map((permission) => (
              <tr key={permission.id}>
                <td>{permission.profileDisplayName}</td>
                <td>
                  <span className={`badge badge--${permission.state}`}>
                    {permission.state}
                  </span>
                </td>
                <td>{new Date(permission.grantedAt).toLocaleString()}</td>
                <td>
                  {permission.state === "enabled" ? (
                    <MutationButton
                      triggerLabel="Revoke"
                      triggerClassName="button button--danger"
                      confirmTitle={`Revoke ${permission.profileDisplayName}`}
                      confirmLabel="Revoke"
                      confirmBody={
                        <p>
                          This user will lose access to this protocol profile.
                        </p>
                      }
                      action={() =>
                        revokePermission(userId, permission.protocolProfileId)
                      }
                      onSuccess={(updated) =>
                        setPermissions((current) =>
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

      {grantableProfiles.length > 0 ? (
        <MutationButton
          triggerLabel="Grant permission"
          triggerClassName="button button--primary"
          confirmTitle="Grant protocol permission"
          confirmLabel="Grant"
          confirmBody={
            <div className="field">
              <label htmlFor="grant-profile-select" className="field__label">
                Profile
              </label>
              <select
                id="grant-profile-select"
                value={effectiveSelection}
                onChange={(event) => setSelectedProfileId(event.target.value)}
              >
                {grantableProfiles.map((profile) => (
                  <option key={profile.id} value={profile.id}>
                    {profile.displayName}
                  </option>
                ))}
              </select>
            </div>
          }
          action={() => grantPermission(userId, effectiveSelection)}
          onSuccess={(granted) =>
            setPermissions((current) => upsertById(current, granted))
          }
        />
      ) : null}
    </>
  );
}
