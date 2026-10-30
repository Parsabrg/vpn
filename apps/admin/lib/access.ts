import "server-only";
import { apiFetch } from "@/lib/api/client";

export interface UserPermissionListItem {
  id: string;
  protocolProfileId: string;
  profileCode: string;
  profileDisplayName: string;
  state: string;
  grantedByAdminId: string | null;
  grantedAt: string;
  expiresAt: string | null;
  revokedAt: string | null;
}

export interface UserAssignmentListItem {
  id: string;
  vpnServerId: string;
  serverCode: string;
  serverDisplayName: string;
  state: string;
  assignedByAdminId: string | null;
  assignedAt: string;
  expiresAt: string | null;
  revokedAt: string | null;
}

export interface PermissionListItem extends UserPermissionListItem {
  userId: string;
  userEmail: string;
}

export interface AssignmentListItem extends UserAssignmentListItem {
  userId: string;
  userEmail: string;
}

export interface PermissionListPage {
  items: PermissionListItem[];
  total: number;
  limit: number;
  offset: number;
}

export interface AssignmentListPage {
  items: AssignmentListItem[];
  total: number;
  limit: number;
  offset: number;
}

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

interface PermissionListItemBody extends UserPermissionListItemBody {
  user_id: string;
  user_email: string;
}

interface AssignmentListItemBody extends UserAssignmentListItemBody {
  user_id: string;
  user_email: string;
}

function toUserPermissionItem(
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

function toUserAssignmentItem(
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

function toPermissionListItem(
  body: PermissionListItemBody,
): PermissionListItem {
  return {
    ...toUserPermissionItem(body),
    userId: body.user_id,
    userEmail: body.user_email,
  };
}

function toAssignmentListItem(
  body: AssignmentListItemBody,
): AssignmentListItem {
  return {
    ...toUserAssignmentItem(body),
    userId: body.user_id,
    userEmail: body.user_email,
  };
}

export async function listUserPermissions(
  userId: string,
): Promise<UserPermissionListItem[]> {
  const body = await apiFetch<{ items: UserPermissionListItemBody[] }>(
    `/v1/admin/users/${encodeURIComponent(userId)}/permissions`,
  );
  return body.items.map(toUserPermissionItem);
}

export async function listUserAssignments(
  userId: string,
): Promise<UserAssignmentListItem[]> {
  const body = await apiFetch<{ items: UserAssignmentListItemBody[] }>(
    `/v1/admin/users/${encodeURIComponent(userId)}/assignments`,
  );
  return body.items.map(toUserAssignmentItem);
}

export async function listAllPermissions(query: {
  limit?: number;
  offset?: number;
}): Promise<PermissionListPage> {
  const body = await apiFetch<{
    items: PermissionListItemBody[];
    total: number;
    limit: number;
    offset: number;
  }>("/v1/admin/permissions", {
    searchParams: { limit: query.limit, offset: query.offset },
  });
  return {
    items: body.items.map(toPermissionListItem),
    total: body.total,
    limit: body.limit,
    offset: body.offset,
  };
}

export async function listAllAssignments(query: {
  limit?: number;
  offset?: number;
}): Promise<AssignmentListPage> {
  const body = await apiFetch<{
    items: AssignmentListItemBody[];
    total: number;
    limit: number;
    offset: number;
  }>("/v1/admin/assignments", {
    searchParams: { limit: query.limit, offset: query.offset },
  });
  return {
    items: body.items.map(toAssignmentListItem),
    total: body.total,
    limit: body.limit,
    offset: body.offset,
  };
}
