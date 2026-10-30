import "server-only";
import { apiFetch } from "@/lib/api/client";

export interface AuditLogListItem {
  id: string;
  actorKind: string;
  actorId: string | null;
  targetKind: string;
  targetId: string;
  eventCode: string;
  outcome: string;
  reasonCode: string | null;
  requestId: string | null;
  recordedAt: string;
}

export interface AuditLogPage {
  items: AuditLogListItem[];
  total: number;
  limit: number;
  offset: number;
}

export interface AuditLogQuery {
  actorKind?: string;
  targetKind?: string;
  eventCode?: string;
  outcome?: string;
  limit?: number;
  offset?: number;
}

interface AuditLogListItemBody {
  id: string;
  actor_kind: string;
  actor_id: string | null;
  target_kind: string;
  target_id: string;
  event_code: string;
  outcome: string;
  reason_code: string | null;
  request_id: string | null;
  recorded_at: string;
}

interface AuditLogListResponseBody {
  items: AuditLogListItemBody[];
  total: number;
  limit: number;
  offset: number;
}

function toItem(body: AuditLogListItemBody): AuditLogListItem {
  return {
    id: body.id,
    actorKind: body.actor_kind,
    actorId: body.actor_id,
    targetKind: body.target_kind,
    targetId: body.target_id,
    eventCode: body.event_code,
    outcome: body.outcome,
    reasonCode: body.reason_code,
    requestId: body.request_id,
    recordedAt: body.recorded_at,
  };
}

export async function listAuditLog(
  query: AuditLogQuery = {},
): Promise<AuditLogPage> {
  const body = await apiFetch<AuditLogListResponseBody>(
    "/v1/admin/audit-log/",
    {
      searchParams: {
        actor_kind: query.actorKind,
        target_kind: query.targetKind,
        event_code: query.eventCode,
        outcome: query.outcome,
        limit: query.limit,
        offset: query.offset,
      },
    },
  );
  return {
    items: body.items.map(toItem),
    total: body.total,
    limit: body.limit,
    offset: body.offset,
  };
}
