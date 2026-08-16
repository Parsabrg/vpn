import "server-only";
import { type ActionResult, toActionResult } from "@/lib/api/action-result";
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

export async function approveAccountRequest(
  id: string,
): Promise<ActionResult<AccountRequestListItem>> {
  "use server";
  return toActionResult(
    apiFetch<AccountRequestItemBody>(
      `/v1/admin/account-requests/${id}/approve`,
      {
        method: "POST",
      },
    ).then(toItem),
  );
}

export async function rejectAccountRequest(
  id: string,
  reason: string | null,
): Promise<ActionResult<AccountRequestListItem>> {
  "use server";
  return toActionResult(
    apiFetch<AccountRequestItemBody>(
      `/v1/admin/account-requests/${id}/reject`,
      {
        method: "POST",
        body: { reason },
      },
    ).then(toItem),
  );
}
