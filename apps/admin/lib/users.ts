import "server-only";
import { apiFetch } from "@/lib/api/client";

export type UserState =
  "pending_activation" | "active" | "suspended" | "disabled";
export type DeviceState = "active" | "revoked";

export interface UserListItem {
  id: string;
  email: string;
  username: string | null;
  state: UserState;
  deviceLimit: number;
  /** Which resolver the account's tunnels get. */
  dnsProfile: DnsProfile;
  expiresAt: string | null;
  activatedAt: string | null;
  disabledAt: string | null;
  createdAt: string;
}

export interface UserListPage {
  items: UserListItem[];
  total: number;
  limit: number;
  offset: number;
}

export interface DeviceListItem {
  id: string;
  name: string;
  platform: string;
  clientVersion: string;
  state: DeviceState;
  revokedAt: string | null;
  /** From evidence: "unknown" whenever the counters were not read lately. */
  activity: DeviceActivity;
  tunnelActiveAt: string | null;
  tunnelCheckedAt: string | null;
  appSeenAt: string | null;
  /** The device's own DNS profile; null follows the account's. */
  dnsProfile: DnsProfile | null;
}

export type { DnsProfile } from "./dns-profiles";
import type { DnsProfile } from "./dns-profiles";

export type DeviceActivity = "active" | "quiet" | "unknown";

export interface UserSessionListItem {
  id: string;
  deviceId: string;
  state: DeviceState;
  expiresAt: string;
  lastSeenAt: string | null;
  revokedAt: string | null;
}

/** What an account has spent on its current allowance, and what is left. */
export interface TrafficAllowance {
  usedBytes: number;
  /**
   * Null means unmetered -- not "a very large allowance". The two render
   * differently and a sentinel would eventually be shown as a number.
   */
  quotaBytes: number | null;
  remainingBytes: number | null;
  /** Set when the allowance was found spent and the credentials revoked. */
  exhaustedAt: string | null;
  /** Everything ever transferred, across every allowance held. */
  lifetimeBytes: number;
}

export interface UserDetail {
  user: UserListItem;
  devices: DeviceListItem[];
  sessions: UserSessionListItem[];
  traffic: TrafficAllowance;
}

export interface UserListQuery {
  state?: string;
  emailPrefix?: string;
  usernamePrefix?: string;
  limit?: number;
  offset?: number;
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

interface UserListResponseBody {
  items: UserListItemBody[];
  total: number;
  limit: number;
  offset: number;
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

interface TrafficAllowanceBody {
  used_bytes: number;
  quota_bytes: number | null;
  remaining_bytes: number | null;
  exhausted_at: string | null;
  lifetime_bytes: number;
}

interface UserDetailResponseBody {
  user: UserListItemBody;
  devices: DeviceListItemBody[];
  sessions: UserSessionListItemBody[];
  traffic: TrafficAllowanceBody;
}

export function toTrafficAllowance(
  body: TrafficAllowanceBody,
): TrafficAllowance {
  return {
    usedBytes: body.used_bytes,
    quotaBytes: body.quota_bytes,
    remainingBytes: body.remaining_bytes,
    exhaustedAt: body.exhausted_at,
    lifetimeBytes: body.lifetime_bytes,
  };
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

export async function listUsers(
  query: UserListQuery = {},
): Promise<UserListPage> {
  const body = await apiFetch<UserListResponseBody>("/v1/admin/users/", {
    searchParams: {
      state: query.state,
      email_prefix: query.emailPrefix,
      username_prefix: query.usernamePrefix,
      limit: query.limit,
      offset: query.offset,
    },
  });
  return {
    items: body.items.map(toUserItem),
    total: body.total,
    limit: body.limit,
    offset: body.offset,
  };
}

export async function getUserDetail(
  userId: string,
): Promise<UserDetail | null> {
  try {
    const body = await apiFetch<UserDetailResponseBody>(
      `/v1/admin/users/${encodeURIComponent(userId)}`,
    );
    return {
      user: toUserItem(body.user),
      devices: body.devices.map(toDeviceItem),
      sessions: body.sessions.map(toSessionItem),
      traffic: toTrafficAllowance(body.traffic),
    };
  } catch {
    return null;
  }
}
