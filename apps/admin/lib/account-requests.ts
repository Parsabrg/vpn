import "server-only";
import { apiFetch } from "@/lib/api/client";

export type AccountRequestState =
  "pending" | "approved" | "rejected" | "expired";

export interface AccountRequestListItem {
  id: string;
  email: string;
  username: string | null;
  state: AccountRequestState;
  createdAt: string;
}

interface AccountRequestItemBody {
  id: string;
  email: string;
  username: string | null;
  state: AccountRequestState;
  created_at: string;
}

interface AccountRequestListResponseBody {
  items: AccountRequestItemBody[];
}

function toItem(body: AccountRequestItemBody): AccountRequestListItem {
  return {
    id: body.id,
    email: body.email,
    username: body.username,
    state: body.state,
    createdAt: body.created_at,
  };
}

export async function listPendingAccountRequests(): Promise<
  AccountRequestListItem[]
> {
  const body = await apiFetch<AccountRequestListResponseBody>(
    "/v1/admin/account-requests/",
  );
  return body.items.map(toItem);
}
