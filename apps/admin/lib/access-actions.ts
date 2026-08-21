"use server";

import { type ActionResult, toActionResult } from "@/lib/api/action-result";
import { apiFetch } from "@/lib/api/client";
import type { UserAssignmentListItem, UserPermissionListItem } from "./access";

interface UserPermissionListItemBody {
  id: string;
  protocol_profile_id: string;
  profile_code: string;
  profile_display_name: string;
  state: string;
  granted_by_admin_id: string | null;
  granted_at: string;
  expires_at: string | null;
  revoked_at: string | null;
}

interface UserAssignmentListItemBody {
  id: string;
  vpn_server_id: string;
  server_code: string;
  server_display_name: string;
  state: string;
  assigned_by_admin_id: string | null;
  assigned_at: string;
  expires_at: string | null;
  revoked_at: string | null;
}

function toPermissionItem(
  body: UserPermissionListItemBody,
): UserPermissionListItem {
  return {
    id: body.id,
    protocolProfileId: body.protocol_profile_id,
    profileCode: body.profile_code,
    profileDisplayName: body.profile_display_name,
    state: body.state,
    grantedByAdminId: body.granted_by_admin_id,
    grantedAt: body.granted_at,
    expiresAt: body.expires_at,
    revokedAt: body.revoked_at,
  };
}

function toAssignmentItem(
  body: UserAssignmentListItemBody,
): UserAssignmentListItem {
  return {
    id: body.id,
    vpnServerId: body.vpn_server_id,
    serverCode: body.server_code,
    serverDisplayName: body.server_display_name,
    state: body.state,
    assignedByAdminId: body.assigned_by_admin_id,
    assignedAt: body.assigned_at,
    expiresAt: body.expires_at,
    revokedAt: body.revoked_at,
  };
}

export async function grantPermission(
  userId: string,
  protocolProfileId: string,
): Promise<ActionResult<UserPermissionListItem>> {
  return toActionResult(
    apiFetch<UserPermissionListItemBody>(
      `/v1/admin/users/${userId}/permissions/${protocolProfileId}/grant`,
      { method: "POST" },
    ).then(toPermissionItem),
  );
}

export async function revokePermission(
  userId: string,
  protocolProfileId: string,
): Promise<ActionResult<UserPermissionListItem>> {
  return toActionResult(
    apiFetch<UserPermissionListItemBody>(
      `/v1/admin/users/${userId}/permissions/${protocolProfileId}/revoke`,
      { method: "POST" },
    ).then(toPermissionItem),
  );
}

export async function assignServer(
  userId: string,
  vpnServerId: string,
): Promise<ActionResult<UserAssignmentListItem>> {
  return toActionResult(
    apiFetch<UserAssignmentListItemBody>(
      `/v1/admin/users/${userId}/assignments/${vpnServerId}/assign`,
      { method: "POST" },
    ).then(toAssignmentItem),
  );
}

export async function revokeAssignment(
  userId: string,
  vpnServerId: string,
): Promise<ActionResult<UserAssignmentListItem>> {
  return toActionResult(
    apiFetch<UserAssignmentListItemBody>(
      `/v1/admin/users/${userId}/assignments/${vpnServerId}/revoke`,
      { method: "POST" },
    ).then(toAssignmentItem),
  );
}
