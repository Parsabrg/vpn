"use client";

import { useState } from "react";
import { grantTrafficQuota } from "@/lib/users-actions";
import type { TrafficAllowance } from "@/lib/users";
import { MutationButton } from "./mutation-button";

const KIB = 1024;

/**
 * Binary units, matching what the servers count and what the app displays.
 * Mixing conventions is how a "1 GB" allowance becomes an argument about
 * seven per cent of it.
 */
const UNITS = [
  { label: "MB", bytes: KIB ** 2 },
  { label: "GB", bytes: KIB ** 3 },
  { label: "TB", bytes: KIB ** 4 },
] as const;

/** Gigabytes: the unit almost every plan is sold in. */
const DEFAULT_UNIT = UNITS[1];

export function formatBytes(bytes: number): string {
  if (bytes < KIB) {
    return `${Math.max(bytes, 0)} B`;
  }
  const units = [
    { label: "TB", bytes: KIB ** 4 },
    { label: "GB", bytes: KIB ** 3 },
    { label: "MB", bytes: KIB ** 2 },
    { label: "KB", bytes: KIB },
  ];
  for (const unit of units) {
    if (bytes >= unit.bytes) {
      const value = bytes / unit.bytes;
      // One decimal below ten and none above: the leading digits are what a
      // person reads, and 412.7 GB is no more useful than 412 GB.
      return `${value < 10 ? value.toFixed(1) : value.toFixed(0)} ${unit.label}`;
    }
  }
  return `${bytes} B`;
}

/**
 * Granting an allowance, and showing what has been spent of it.
 *
 * A grant rather than an edit: whatever is entered here becomes the whole
 * allowance and the count starts again at zero. That is what lets an operator
 * type the size of the plan they sold instead of a running total they would
 * have to work out.
 */
export function TrafficAllowancePanel({
  userId,
  initialAllowance,
}: {
  userId: string;
  initialAllowance: TrafficAllowance;
}) {
  const [allowance, setAllowance] = useState(initialAllowance);
  const [amount, setAmount] = useState("100");
  const [unitLabel, setUnitLabel] = useState("GB");

  const unit =
    UNITS.find((candidate) => candidate.label === unitLabel) ?? DEFAULT_UNIT;
  const parsedAmount = Number(amount);
  const amountIsUsable = Number.isFinite(parsedAmount) && parsedAmount >= 0;
  const quotaBytes = amountIsUsable ? Math.round(parsedAmount * unit.bytes) : 0;

  const isMetered = allowance.quotaBytes !== null;
  const isCutOff = allowance.exhaustedAt !== null;

  return (
    <>
      <dl className="detail-grid">
        <div>
          <dt>Allowance</dt>
          <dd>
            {isMetered
              ? formatBytes(allowance.quotaBytes as number)
              : "Unmetered"}
          </dd>
        </div>
        <div>
          <dt>Used</dt>
          <dd>{formatBytes(allowance.usedBytes)}</dd>
        </div>
        <div>
          <dt>Remaining</dt>
          {/* No figure at all when unmetered. A dash rather than a number,
              because any number here would be an invented limit. */}
          <dd>
            {allowance.remainingBytes === null
              ? "—"
              : formatBytes(allowance.remainingBytes)}
          </dd>
        </div>
        <div>
          <dt>Transferred in total</dt>
          {/* Survives a grant, so a top-up does not look like the history
              was deleted. */}
          <dd>{formatBytes(allowance.lifetimeBytes)}</dd>
        </div>
      </dl>

      {isCutOff ? (
        <p role="status">
          This account ran out on{" "}
          {new Date(allowance.exhaustedAt as string).toLocaleString()} and its
          VPN credentials were revoked. Granting a new allowance lets it connect
          again.
        </p>
      ) : null}

      <MutationButton
        triggerLabel={isCutOff ? "Grant a new allowance" : "Change allowance"}
        triggerClassName="button button--primary"
        confirmTitle="Grant a traffic allowance"
        confirmLabel="Grant"
        confirmBody={
          <>
            <div className="field">
              <label htmlFor="traffic-quota-amount" className="field__label">
                Allowance
              </label>
              <input
                id="traffic-quota-amount"
                type="number"
                min="0"
                step="any"
                value={amount}
                onChange={(event) => setAmount(event.target.value)}
              />
              <select
                aria-label="Unit"
                value={unitLabel}
                onChange={(event) => setUnitLabel(event.target.value)}
              >
                {UNITS.map((candidate) => (
                  <option key={candidate.label} value={candidate.label}>
                    {candidate.label}
                  </option>
                ))}
              </select>
            </div>
            <p>
              This replaces the current allowance and the count starts again at
              zero. {formatBytes(allowance.usedBytes)} used so far will no
              longer count against it.
            </p>
          </>
        }
        action={() => grantTrafficQuota(userId, quotaBytes)}
        onSuccess={(updated) => setAllowance(updated)}
      />

      {isMetered ? (
        <MutationButton
          triggerLabel="Remove the limit"
          triggerClassName="button"
          confirmTitle="Make this account unmetered"
          confirmLabel="Remove limit"
          confirmBody={
            <p>
              This account will have no traffic limit at all. Its usage is still
              measured, and nothing will revoke its credentials for transferring
              too much.
            </p>
          }
          action={() => grantTrafficQuota(userId, null)}
          onSuccess={(updated) => setAllowance(updated)}
        />
      ) : null}
    </>
  );
}
