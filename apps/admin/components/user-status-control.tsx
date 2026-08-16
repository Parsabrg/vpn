"use client";

import { useState } from "react";
import { disableUser, reactivateUser } from "@/lib/users-actions";
import type { UserState } from "@/lib/users";
import { MutationButton } from "./mutation-button";

export function UserStatusControl({
  userId,
  initialState,
}: {
  userId: string;
  initialState: UserState;
}) {
  const [state, setState] = useState(initialState);

  return (
    <span className="user-status-control">
      <span className={`badge badge--${state}`}>{state}</span>
      {state === "active" ? (
        <MutationButton
          triggerLabel="Disable"
          triggerClassName="button button--danger"
          confirmTitle="Disable this user"
          confirmLabel="Disable"
          confirmBody={
            <p>
              This immediately revokes every active device and session for this
              user.
            </p>
          }
          action={() => disableUser(userId)}
          onSuccess={(user) => {
            setState(user.state);
          }}
        />
      ) : null}
      {state === "disabled" ? (
        <MutationButton
          triggerLabel="Reactivate"
          triggerClassName="button button--primary"
          confirmTitle="Reactivate this user"
          confirmLabel="Reactivate"
          confirmBody={<p>The user will be able to sign in again.</p>}
          action={() => reactivateUser(userId)}
          onSuccess={(user) => {
            setState(user.state);
          }}
        />
      ) : null}
    </span>
  );
}
