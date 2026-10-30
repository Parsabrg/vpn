"use server";

import { type ActionResult, toActionResult } from "@/lib/api/action-result";
import { apiFetch } from "@/lib/api/client";
import type {
  AccountRequestListItem,
  AccountRequestState,
} from "./account-requests";

interface AccountRequestItemBody {
  id: string;
  email: string;
  username: string | null;
  state: AccountRequestState;
  created_at: string;
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

export async function approveAccountRequest(
  id: string,
): Promise<ActionResult<AccountRequestListItem>> {
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
