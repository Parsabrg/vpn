"use server";

import { type ActionResult, toActionResult } from "@/lib/api/action-result";
import { apiFetch } from "@/lib/api/client";
import type {
  DeviceActivity,
  DeviceListItem,
  DeviceState,
  TrafficAllowance,
  UserListItem,
  UserSessionListItem,
  UserState,
} from "./users";
import type { DnsProfile } from "./dns-profiles";
import { toTrafficAllowance } from "./users";

interface TrafficAllowanceBody {
  used_bytes: number;
  quota_bytes: number | null;
  remaining_bytes: number | null;
  exhausted_at: string | null;
  lifetime_bytes: number;
}

interface UserListItemBody {
  id: string;
  email: string;
  username: string | null;
  state: UserState;
  device_limit: number;
  dns_profile?: DnsProfile;
  expires_at: string | null;
  activated_at: string | null;
  disabled_at: string | null;
  created_at: string;
}

interface DeviceListItemBody {
  id: string;
  name: string;
  platform: string;
  client_version: string;
  state: DeviceState;
  revoked_at: string | null;
  activity?: DeviceActivity;
  tunnel_active_at?: string | null;
  tunnel_checked_at?: string | null;
  app_seen_at?: string | null;
  dns_profile?: DnsProfile | null;
}

interface UserSessionListItemBody {
  id: string;
  device_id: string;
  state: DeviceState;
  expires_at: string;
  last_seen_at: string | null;
  revoked_at: string | null;
}

function toUserItem(body: UserListItemBody): UserListItem {
  return {
    id: body.id,
    email: body.email,
    username: body.username,
    state: body.state,
    deviceLimit: body.device_limit,
    dnsProfile: body.dns_profile ?? "default",
    expiresAt: body.expires_at,
    activatedAt: body.activated_at,
    disabledAt: body.disabled_at,
    createdAt: body.created_at,
  };
}

function toDeviceItem(body: DeviceListItemBody): DeviceListItem {
  return {
    id: body.id,
    name: body.name,
    platform: body.platform,
    clientVersion: body.client_version,
    state: body.state,
    revokedAt: body.revoked_at,
    activity: body.activity ?? "unknown",
    tunnelActiveAt: body.tunnel_active_at ?? null,
    tunnelCheckedAt: body.tunnel_checked_at ?? null,
    appSeenAt: body.app_seen_at ?? null,
    dnsProfile: body.dns_profile ?? null,
  };
}

function toSessionItem(body: UserSessionListItemBody): UserSessionListItem {
  return {
    id: body.id,
    deviceId: body.device_id,
    state: body.state,
    expiresAt: body.expires_at,
    lastSeenAt: body.last_seen_at,
    revokedAt: body.revoked_at,
  };
}

export async function disableUser(
  userId: string,
): Promise<ActionResult<UserListItem>> {
  return toActionResult(
    apiFetch<UserListItemBody>(`/v1/admin/users/${userId}/disable`, {
      method: "POST",
    }).then(toUserItem),
  );
}

export async function reactivateUser(
  userId: string,
): Promise<ActionResult<UserListItem>> {
  return toActionResult(
    apiFetch<UserListItemBody>(`/v1/admin/users/${userId}/reactivate`, {
      method: "POST",
    }).then(toUserItem),
  );
}

/**
 * Grant a traffic allowance, replacing whatever the account had.
 *
 * A grant, not an edit: the new allowance starts at zero used, so the figure
 * passed here is the size of the plan being sold rather than a running total
 * an operator would have to compute.
 *
 * `null` means unmetered. `0` means metered at zero -- nothing allowed --
 * and the two are deliberately not the same value.
 */
export async function grantTrafficQuota(
  userId: string,
  quotaBytes: number | null,
): Promise<ActionResult<TrafficAllowance>> {
  return toActionResult(
    apiFetch<TrafficAllowanceBody>(
      `/v1/admin/users/${encodeURIComponent(userId)}/traffic-quota`,
      {
        method: "POST",
        body: { quota_bytes: quotaBytes },
      },
    ).then(toTrafficAllowance),
  );
}

/** The resolver the account's tunnels get, from each device's next connection. */
export async function setDnsProfile(
  userId: string,
  dnsProfile: DnsProfile,
): Promise<ActionResult<UserListItem>> {
  return toActionResult(
    apiFetch<UserListItemBody>(
      `/v1/admin/users/${encodeURIComponent(userId)}/dns-profile`,
      {
        method: "POST",
        body: { dns_profile: dnsProfile },
      },
    ).then(toUserItem),
  );
}

/** A device's own DNS profile; `null` follows the account's. */
export async function setDeviceDnsProfile(
  userId: string,
  deviceId: string,
  dnsProfile: DnsProfile | null,
): Promise<ActionResult<DeviceListItem>> {
  return toActionResult(
    apiFetch<DeviceListItemBody>(
      `/v1/admin/users/${encodeURIComponent(userId)}/devices/${encodeURIComponent(deviceId)}/dns-profile`,
      {
        method: "POST",
        body: { dns_profile: dnsProfile },
      },
    ).then(toDeviceItem),
  );
}

/** How many devices the account may have active at once (1-100). */
export async function setDeviceLimit(
  userId: string,
  deviceLimit: number,
): Promise<ActionResult<UserListItem>> {
  return toActionResult(
    apiFetch<UserListItemBody>(
      `/v1/admin/users/${encodeURIComponent(userId)}/device-limit`,
      {
        method: "POST",
        body: { device_limit: deviceLimit },
      },
    ).then(toUserItem),
  );
}

/**
 * When the account's access ends, as an ISO time; `null` means never.
 * A past time ends it at once.
 */
export async function setExpiry(
  userId: string,
  expiresAt: string | null,
): Promise<ActionResult<UserListItem>> {
  return toActionResult(
    apiFetch<UserListItemBody>(
      `/v1/admin/users/${encodeURIComponent(userId)}/expiry`,
      {
        method: "POST",
        body: { expires_at: expiresAt },
      },
    ).then(toUserItem),
  );
}

export async function revokeDevice(
  userId: string,
  deviceId: string,
): Promise<ActionResult<DeviceListItem>> {
  return toActionResult(
    apiFetch<DeviceListItemBody>(
      `/v1/admin/users/${userId}/devices/${deviceId}/revoke`,
      {
        method: "POST",
      },
    ).then(toDeviceItem),
  );
}

export async function revokeUserSession(
  userId: string,
  sessionId: string,
): Promise<ActionResult<UserSessionListItem>> {
  return toActionResult(
    apiFetch<UserSessionListItemBody>(
      `/v1/admin/users/${userId}/sessions/${sessionId}/revoke`,
      {
        method: "POST",
      },
    ).then(toSessionItem),
  );
}
