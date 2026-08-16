import "server-only";
import { type ActionResult, toActionResult } from "@/lib/api/action-result";
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
}

export interface UserSessionListItem {
  id: string;
  deviceId: string;
  state: DeviceState;
  expiresAt: string;
  lastSeenAt: string | null;
  revokedAt: string | null;
}

export interface UserDetail {
  user: UserListItem;
  devices: DeviceListItem[];
  sessions: UserSessionListItem[];
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
}

interface UserSessionListItemBody {
  id: string;
  device_id: string;
  state: DeviceState;
  expires_at: string;
  last_seen_at: string | null;
  revoked_at: string | null;
}

interface UserDetailResponseBody {
  user: UserListItemBody;
  devices: DeviceListItemBody[];
  sessions: UserSessionListItemBody[];
}

function toUserItem(body: UserListItemBody): UserListItem {
  return {
    id: body.id,
    email: body.email,
    username: body.username,
    state: body.state,
    deviceLimit: body.device_limit,
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
    };
  } catch {
    return null;
  }
}

export async function disableUser(
  userId: string,
): Promise<ActionResult<UserListItem>> {
  "use server";
  return toActionResult(
    apiFetch<UserListItemBody>(`/v1/admin/users/${userId}/disable`, {
      method: "POST",
    }).then(toUserItem),
  );
}

export async function reactivateUser(
  userId: string,
): Promise<ActionResult<UserListItem>> {
  "use server";
  return toActionResult(
    apiFetch<UserListItemBody>(`/v1/admin/users/${userId}/reactivate`, {
      method: "POST",
    }).then(toUserItem),
  );
}

export async function revokeDevice(
  userId: string,
  deviceId: string,
): Promise<ActionResult<DeviceListItem>> {
  "use server";
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
  "use server";
  return toActionResult(
    apiFetch<UserSessionListItemBody>(
      `/v1/admin/users/${userId}/sessions/${sessionId}/revoke`,
      {
        method: "POST",
      },
    ).then(toSessionItem),
  );
}
