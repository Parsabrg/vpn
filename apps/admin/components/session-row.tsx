"use client";

import { useState } from "react";
import { revokeUserSession } from "@/lib/users-actions";
import type { UserSessionListItem } from "@/lib/users";
import { MutationButton } from "./mutation-button";

export function SessionRow({
  userId,
  session,
}: {
  userId: string;
  session: UserSessionListItem;
}) {
  const [current, setCurrent] = useState(session);

  return (
    <tr>
      <td>{current.deviceId}</td>
      <td>
        <span className={`badge badge--${current.state}`}>{current.state}</span>
      </td>
      <td>{new Date(current.expiresAt).toLocaleString()}</td>
      <td>
        {current.lastSeenAt
          ? new Date(current.lastSeenAt).toLocaleString()
          : "—"}
      </td>
      <td>
        {current.state === "active" ? (
          <MutationButton
            triggerLabel="Revoke"
            triggerClassName="button button--danger"
            confirmTitle="Revoke this session"
            confirmLabel="Revoke"
            confirmBody={
              <p>The device using this session is signed out immediately.</p>
            }
            action={() => revokeUserSession(userId, current.id)}
            onSuccess={setCurrent}
          />
        ) : (
          "—"
        )}
      </td>
    </tr>
  );
}
