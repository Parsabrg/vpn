"use client";

import { useState } from "react";
import { revokeDevice } from "@/lib/users-actions";
import type { DeviceListItem } from "@/lib/users";
import { MutationButton } from "./mutation-button";

export function DeviceRow({
  userId,
  device,
}: {
  userId: string;
  device: DeviceListItem;
}) {
  const [current, setCurrent] = useState(device);

  return (
    <tr>
      <td>{current.name}</td>
      <td>{current.platform}</td>
      <td>{current.clientVersion}</td>
      <td>
        <span className={`badge badge--${current.state}`}>{current.state}</span>
      </td>
      <td>
        {current.state === "active" ? (
          <MutationButton
            triggerLabel="Revoke"
            triggerClassName="button button--danger"
            confirmTitle={`Revoke ${current.name}`}
            confirmLabel="Revoke"
            confirmBody={
              <p>This immediately revokes every session on this device.</p>
            }
            action={() => revokeDevice(userId, current.id)}
            onSuccess={setCurrent}
          />
        ) : (
          "—"
        )}
      </td>
    </tr>
  );
}
