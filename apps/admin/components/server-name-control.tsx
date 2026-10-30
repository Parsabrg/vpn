"use client";

import { useState } from "react";
import { renameServer } from "@/lib/topology-actions";
import { MutationButton } from "./mutation-button";

/** The server's name as the app shows it, with a way to change it. */
export function ServerNameControl({
  serverId,
  code,
  initialName,
}: {
  serverId: string;
  code: string;
  initialName: string;
}) {
  const [name, setName] = useState(initialName);
  const [draft, setDraft] = useState(initialName);

  return (
    <div className="server-card__name">
      <h2>{name}</h2>
      <MutationButton
        triggerLabel="Rename"
        triggerClassName="button button--secondary"
        confirmTitle={`Rename ${code}`}
        confirmLabel="Save"
        confirmBody={
          <div className="field">
            <label htmlFor={`server-name-${serverId}`} className="field__label">
              Name shown in the app
            </label>
            <input
              id={`server-name-${serverId}`}
              value={draft}
              maxLength={96}
              onChange={(event) => setDraft(event.target.value)}
            />
            <p>The server code ({code}) stays the same.</p>
          </div>
        }
        action={() => renameServer(serverId, draft)}
        onSuccess={(updated) => setName(updated)}
      />
    </div>
  );
}
