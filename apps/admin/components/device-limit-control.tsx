"use client";

import { useState } from "react";
import { setDeviceLimit } from "@/lib/users-actions";
import { MutationButton } from "./mutation-button";

/**
 * The account's device limit, and changing it. Lowering it signs no device
 * out; it stops the next one registering.
 */
export function DeviceLimitControl({
  userId,
  initialLimit,
}: {
  userId: string;
  initialLimit: number;
}) {
  const [limit, setLimit] = useState(initialLimit);
  const [draft, setDraft] = useState(String(initialLimit));

  return (
    <>
      {limit}{" "}
      <MutationButton
        triggerLabel="Change"
        triggerClassName="button"
        confirmTitle="Change the device limit"
        confirmLabel="Save"
        confirmBody={
          <>
            <div className="field">
              <label htmlFor="device-limit" className="field__label">
                Devices allowed at once
              </label>
              <input
                id="device-limit"
                type="number"
                min="1"
                max="100"
                step="1"
                value={draft}
                onChange={(event) => setDraft(event.target.value)}
              />
            </div>
            <p>
              Devices already signed in stay signed in. A reinstalled app reuses
              its old device and does not count twice.
            </p>
          </>
        }
        action={() => setDeviceLimit(userId, Number(draft))}
        onSuccess={(updated) => setLimit(updated.deviceLimit)}
      />
    </>
  );
}
