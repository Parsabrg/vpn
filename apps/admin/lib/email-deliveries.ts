import "server-only";
import { apiFetch } from "@/lib/api/client";

export interface EmailDeliveryListItem {
  id: string;
  templateCode: string;
  recipientAddress: string;
  subjectKind: string;
  subjectId: string;
  state: string;
  attemptCount: number;
  availableAt: string;
  sentAt: string | null;
  providerMessageId: string | null;
  resultCode: string | null;
}

export interface EmailDeliveryPage {
  items: EmailDeliveryListItem[];
  total: number;
  limit: number;
  offset: number;
}

export interface EmailDeliveryQuery {
  state?: string;
  templateCode?: string;
  subjectKind?: string;
  limit?: number;
  offset?: number;
}

interface EmailDeliveryListItemBody {
  id: string;
  template_code: string;
  recipient_address: string;
  subject_kind: string;
  subject_id: string;
  state: string;
  attempt_count: number;
  available_at: string;
  sent_at: string | null;
  provider_message_id: string | null;
  result_code: string | null;
}

interface EmailDeliveryListResponseBody {
  items: EmailDeliveryListItemBody[];
  total: number;
  limit: number;
  offset: number;
}

function toItem(body: EmailDeliveryListItemBody): EmailDeliveryListItem {
  return {
    id: body.id,
    templateCode: body.template_code,
    recipientAddress: body.recipient_address,
    subjectKind: body.subject_kind,
    subjectId: body.subject_id,
    state: body.state,
    attemptCount: body.attempt_count,
    availableAt: body.available_at,
    sentAt: body.sent_at,
    providerMessageId: body.provider_message_id,
    resultCode: body.result_code,
  };
}

export async function listEmailDeliveries(
  query: EmailDeliveryQuery = {},
): Promise<EmailDeliveryPage> {
  const body = await apiFetch<EmailDeliveryListResponseBody>(
    "/v1/admin/email-deliveries/",
    {
      searchParams: {
        state: query.state,
        template_code: query.templateCode,
        subject_kind: query.subjectKind,
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
