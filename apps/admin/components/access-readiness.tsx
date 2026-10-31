"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { assignServer, grantPermissions } from "@/lib/access-actions";
import { endedSession } from "@/lib/end-session";

/**
 * Says when a user cannot connect yet, and fixes it in one click. Approving
 * a request grants nothing, and a new user saw an empty app with no hint
 * on either side of what was missing (2026-10-29).
 */
export function AccessReadiness({
  userId,
  missingProfileIds,
  missingServerIds,
  hasProtocol,
  hasServer,
}: {
  userId: string;
  missingProfileIds: string[];
  missingServerIds: string[];
  hasProtocol: boolean;
  hasServer: boolean;
}) {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (hasProtocol && hasServer) {
    return null;
  }

  async function run(
    step: () => Promise<{ ok: boolean; code?: string; message?: string }>,
  ) {
    setPending(true);
    setError(null);
    const result = await step();
    setPending(false);
    if (!result.ok) {
      if (endedSession(result)) {
        return;
      }
      setError(result.message ?? "Something went wrong.");
      return;
    }
    router.refresh();
  }

  const missing = [
    hasProtocol ? null : "no protocol is granted",
    hasServer ? null : "no server is assigned",
  ].filter(Boolean);

  return (
    <div className="notice" role="status">
      <p>
        <strong>This user can&apos;t connect yet:</strong>{" "}
        {missing.join(" and ")}.
      </p>
      <div className="readiness__actions">
        {!hasProtocol && missingProfileIds.length > 0 ? (
          <button
            type="button"
            className="button button--primary"
            disabled={pending}
            onClick={() =>
              run(() => grantPermissions(userId, missingProfileIds))
            }
          >
            Grant all protocols
          </button>
        ) : null}
        {!hasServer && missingServerIds.length > 0 ? (
          <button
            type="button"
            className="button button--primary"
            disabled={pending}
            onClick={() =>
              run(async () => {
                for (const serverId of missingServerIds) {
                  const result = await assignServer(userId, serverId);
                  if (!result.ok) {
                    return result;
                  }
                }
                return { ok: true };
              })
            }
          >
            Assign all servers
          </button>
        ) : null}
      </div>
      {error ? <p role="alert">{error}</p> : null}
    </div>
  );
}
