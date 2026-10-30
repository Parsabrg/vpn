"use server";

import { type ActionResult, toActionResult } from "@/lib/api/action-result";
import { apiFetch } from "@/lib/api/client";

export type ServerState = "active" | "maintenance" | "disabled";

/** Put a server into service, into maintenance, or out of it. */
export async function setServerState(
  serverId: string,
  state: ServerState,
): Promise<ActionResult<ServerState>> {
  return toActionResult(
    apiFetch<{ state: ServerState }>(
      `/v1/admin/vpn-servers/${encodeURIComponent(serverId)}/state`,
      { method: "POST", body: { state } },
    ).then((body) => body.state),
  );
}

export interface ReconciliationCounts {
  checked: number;
  inSync: number;
  repaired: number;
  repairFailed: number;
  ambiguous: number;
  errored: number;
}

export interface ReconcileNowResult {
  wireguard: ReconciliationCounts;
  xray: ReconciliationCounts;
}

interface ReconciliationCountsBody {
  checked: number;
  in_sync: number;
  repaired: number;
  repair_failed: number;
  ambiguous: number;
  errored: number;
}

function toCounts(body: ReconciliationCountsBody): ReconciliationCounts {
  return {
    checked: body.checked,
    inSync: body.in_sync,
    repaired: body.repaired,
    repairFailed: body.repair_failed,
    ambiguous: body.ambiguous,
    errored: body.errored,
  };
}

/** The scheduled reconciliation, now: everything, or one credential. */
export async function reconcileNow(
  targetId?: string,
): Promise<ActionResult<ReconcileNowResult>> {
  return toActionResult(
    apiFetch<{
      wireguard: ReconciliationCountsBody;
      xray: ReconciliationCountsBody;
    }>("/v1/admin/reconciliation/run", {
      method: "POST",
      body: targetId ? { target_id: targetId } : {},
    }).then((body) => ({
      wireguard: toCounts(body.wireguard),
      xray: toCounts(body.xray),
    })),
  );
}

/** The name the app shows for a server; its code stays as it is. */
export async function renameServer(
  serverId: string,
  displayName: string,
): Promise<ActionResult<string>> {
  return toActionResult(
    apiFetch<{ display_name: string }>(
      `/v1/admin/vpn-servers/${encodeURIComponent(serverId)}/name`,
      { method: "POST", body: { display_name: displayName } },
    ).then((body) => body.display_name),
  );
}
