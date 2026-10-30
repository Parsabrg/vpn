"use client";

import { useState } from "react";
import { setExpiry } from "@/lib/users-actions";
import { MutationButton } from "./mutation-button";

/** `<input type="datetime-local">` wants local time without a zone. */
function toLocalInput(iso: string): string {
  const date = new Date(iso);
  date.setMinutes(date.getMinutes() - date.getTimezoneOffset());
  return date.toISOString().slice(0, 16);
}

/**
 * When the account's access ends. Past that time sign-in stops and its VPN
 * credentials are taken away on the next expiry run.
 */
export function ExpiryControl({
  userId,
  initialExpiresAt,
}: {
  userId: string;
  initialExpiresAt: string | null;
}) {
  const [expiresAt, setExpiresAt] = useState(initialExpiresAt);
  const [draft, setDraft] = useState(
    initialExpiresAt ? toLocalInput(initialExpiresAt) : "",
  );

  return (
    <>
      {expiresAt ? new Date(expiresAt).toLocaleString() : "Never"}{" "}
      <MutationButton
        triggerLabel={expiresAt ? "Change" : "Set expiry"}
        triggerClassName="button"
        confirmTitle="Set when access ends"
        confirmLabel="Save"
        confirmBody={
          <>
            <div className="field">
              <label htmlFor="account-expiry" className="field__label">
                Access ends (your local time)
              </label>
              <input
                id="account-expiry"
                type="datetime-local"
                value={draft}
                onChange={(event) => setDraft(event.target.value)}
              />
            </div>
            <p>
              After this time the account cannot sign in and its devices lose
              their connection. A time in the past ends access now.
            </p>
          </>
        }
        // An empty or invalid field sends an unparseable date; the API
        // refuses it and the dialog shows why.
        action={() =>
          setExpiry(
            userId,
            draft && !Number.isNaN(new Date(draft).getTime())
              ? new Date(draft).toISOString()
              : draft,
          )
        }
        onSuccess={(updated) => setExpiresAt(updated.expiresAt)}
      />
      {expiresAt ? (
        <MutationButton
          triggerLabel="Remove expiry"
          triggerClassName="button"
          confirmTitle="Remove the expiry date"
          confirmLabel="Remove"
          confirmBody={
            <p>This account&apos;s access will not end on its own.</p>
          }
          action={() => setExpiry(userId, null)}
          onSuccess={(updated) => {
            setExpiresAt(updated.expiresAt);
            setDraft("");
          }}
        />
      ) : null}
    </>
  );
}
