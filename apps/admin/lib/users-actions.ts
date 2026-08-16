"use server";

import { type ActionResult, toActionResult } from "@/lib/api/action-result";
import { apiFetch } from "@/lib/api/client";
import type {
  DeviceListItem,
  DeviceState,
  UserListItem,
  UserSessionListItem,
  UserState,
} from "./users";

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
