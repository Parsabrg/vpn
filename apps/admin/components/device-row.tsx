"use client";

import { useState } from "react";
import { revokeDevice } from "@/lib/users-actions";
import type { DeviceListItem } from "@/lib/users";
import { DnsProfileControl } from "./dns-profile-control";
import { MutationButton } from "./mutation-button";

/** "2 min ago", or "—" with no evidence at all. */
export function ago(iso: string | null, now: number = Date.now()): string {
  if (!iso) {
    return "—";
  }
  const seconds = Math.max(
    0,
    Math.round((now - new Date(iso).getTime()) / 1000),
  );
  if (seconds < 60) return `${seconds} s ago`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)} h ago`;
  return `${Math.round(seconds / 86400)} d ago`;
}

const ACTIVITY_LABEL = {
  active: "Active",
  quiet: "Quiet",
  unknown: "Unknown",
} as const;

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
        {/* The evidence goes beside the word: "Quiet" means the counters were
            read and nothing moved, "Unknown" that nobody has read them lately. */}
        <span
          className={`badge badge--${current.activity}`}
          title={`Counters last read ${ago(current.tunnelCheckedAt)}`}
        >
          {ACTIVITY_LABEL[current.activity]}
        </span>{" "}
        <small>
          traffic {ago(current.tunnelActiveAt)} · app {ago(current.appSeenAt)}
        </small>
      </td>
      <td>
        {current.state === "active" ? (
          <DnsProfileControl
            userId={userId}
            deviceId={current.id}
            initialProfile={current.dnsProfile}
          />
        ) : (
          "—"
        )}
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
