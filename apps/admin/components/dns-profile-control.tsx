"use client";

import { useState } from "react";
import { setDeviceDnsProfile, setDnsProfile } from "@/lib/users-actions";
import { DNS_PROFILE_LABEL, type DnsProfile } from "@/lib/dns-profiles";
import type { ActionResult } from "@/lib/api/action-result";
import { MutationButton } from "./mutation-button";

const PROFILES: DnsProfile[] = ["default", "ads", "family"];

/**
 * Which resolver a tunnel is given (roadmap 13), for an account or, with
 * `deviceId`, one of its devices -- where "Follow the account" clears it.
 * Applies from each device's next connection.
 */
export function DnsProfileControl({
  userId,
  deviceId,
  initialProfile,
}: {
  userId: string;
  deviceId?: string;
  initialProfile: DnsProfile | null;
}) {
  const [profile, setProfile] = useState(initialProfile);
  const [draft, setDraft] = useState<string>(initialProfile ?? "");
  const id = deviceId ? `dns-profile-${deviceId}` : "dns-profile";

  return (
    <>
      {profile ? DNS_PROFILE_LABEL[profile] : "Follows the account"}{" "}
      <MutationButton
        triggerLabel="Change"
        triggerClassName="button"
        confirmTitle={deviceId ? "This device's DNS" : "DNS for this account"}
        confirmLabel="Save"
        confirmBody={
          <>
            <div className="field">
              <label htmlFor={id} className="field__label">
                Resolver
              </label>
              <select
                id={id}
                value={draft}
                onChange={(event) => setDraft(event.target.value)}
              >
                {deviceId ? <option value="">Follow the account</option> : null}
                {PROFILES.map((value) => (
                  <option key={value} value={value}>
                    {DNS_PROFILE_LABEL[value]}
                  </option>
                ))}
              </select>
            </div>
            <p>
              Applies from each device&apos;s next connection. Protocols ending
              in &quot;-adblock&quot; keep blocking ads whatever is chosen here.
            </p>
          </>
        }
        action={async (): Promise<
          ActionResult<{ dnsProfile: DnsProfile | null }>
        > => {
          const result = deviceId
            ? await setDeviceDnsProfile(
                userId,
                deviceId,
                draft === "" ? null : (draft as DnsProfile),
              )
            : await setDnsProfile(userId, (draft || "default") as DnsProfile);
          return result.ok
            ? { ok: true, data: { dnsProfile: result.data.dnsProfile } }
            : result;
        }}
        onSuccess={(updated) => setProfile(updated.dnsProfile)}
      />
    </>
  );
}
