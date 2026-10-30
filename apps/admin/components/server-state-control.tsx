"use client";

import { useState } from "react";
import { type ServerState, setServerState } from "@/lib/topology-actions";
import { MutationButton } from "./mutation-button";

/** What each state does, said where the choice is made. */
const MEANING: Record<ServerState, string> = {
  active: "Offered to the app and takes new connections.",
  maintenance:
    "Takes no new connections and leaves the app's server list. Tunnels already on it keep running, and their traffic and revocations are still handled.",
  disabled:
    "Out of service: not offered, and its traffic and revocations are no longer handled. For a server being retired or rebuilt.",
};

export function ServerStateControl({
  serverId,
  code,
  initialState,
}: {
  serverId: string;
  code: string;
  initialState: string;
}) {
  const [state, setState] = useState(initialState);
  const [draft, setDraft] = useState<ServerState>(
    initialState === "active" ? "maintenance" : "active",
  );

  return (
    <>
      <span className={`badge badge--${state}`}>{state}</span>{" "}
      <MutationButton
        triggerLabel="Change"
        triggerClassName="button"
        confirmTitle={`Change the state of ${code}`}
        confirmLabel="Save"
        confirmBody={
          <>
            <div className="field">
              <label
                htmlFor={`server-state-${serverId}`}
                className="field__label"
              >
                New state
              </label>
              <select
                id={`server-state-${serverId}`}
                value={draft}
                onChange={(event) =>
                  setDraft(event.target.value as ServerState)
                }
              >
                <option value="active">Active</option>
                <option value="maintenance">Maintenance</option>
                <option value="disabled">Disabled</option>
              </select>
            </div>
            <p>{MEANING[draft]}</p>
          </>
        }
        action={() => setServerState(serverId, draft)}
        onSuccess={(updated) => setState(updated)}
      />
    </>
  );
}
