"use client";

import { useState } from "react";
import {
  type ReconcileNowResult,
  type ReconciliationCounts,
  reconcileNow,
} from "@/lib/topology-actions";
import { MutationButton } from "./mutation-button";

/** One line an operator reads at a glance, e.g. "14 checked: 13 in sync, 1 repaired." */
export function describeReconciliation(result: ReconcileNowResult): string {
  const total = (key: keyof ReconciliationCounts) =>
    result.wireguard[key] + result.xray[key];
  const parts = [
    [total("inSync"), "in sync"],
    [total("repaired"), "repaired"],
    [total("repairFailed"), "repair failed"],
    [total("ambiguous"), "ambiguous"],
    [total("errored"), "errored"],
  ]
    .filter(([count]) => count !== 0)
    .map(([count, label]) => `${count} ${label}`);
  return `${total("checked")} checked${parts.length ? `: ${parts.join(", ")}` : ""}.`;
}

/**
 * The scheduled sweep, run now -- for every live credential, or with
 * `targetId` for one. It repairs only what the sweep would repair on its own.
 */
export function ReconcileNowControl({ targetId }: { targetId?: string }) {
  const [summary, setSummary] = useState<string | null>(null);

  return (
    <>
      <MutationButton
        triggerLabel={targetId ? "Check again" : "Run reconciliation now"}
        triggerClassName="button"
        confirmTitle={
          targetId ? "Check this credential again" : "Run reconciliation now"
        }
        confirmLabel="Run"
        confirmBody={
          <p>
            {targetId
              ? "Asks its server about this one credential now. "
              : "Asks every running server about every live credential now. "}
            Safe drift is repaired and anything uncertain is only recorded,
            exactly as the automatic run every 15 minutes does. Refresh the page
            afterwards to see the new checks in the history.
          </p>
        }
        action={() => reconcileNow(targetId)}
        onSuccess={(result) => {
          setSummary(describeReconciliation(result));
        }}
      />
      {summary ? <span role="status"> {summary}</span> : null}
    </>
  );
}
