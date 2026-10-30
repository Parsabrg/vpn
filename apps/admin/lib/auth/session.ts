import "server-only";
import { apiFetch } from "@/lib/api/client";
import { ApiError } from "@/lib/api/http-error";
import type { AdminRole, AdminSession } from "./types";

interface AdminSessionResponseBody {
  admin_id: string;
  role: AdminRole;
  csrf_token: string | null;
  step_up: boolean;
}

/** Returns `null` for any auth failure, including a temporarily unavailable API. */
export async function getAdminSession(): Promise<AdminSession | null> {
  try {
    const body = await apiFetch<AdminSessionResponseBody>(
      "/v1/admin/auth/session",
    );
    return { adminId: body.admin_id, role: body.role, stepUp: body.step_up };
  } catch (error) {
    if (error instanceof ApiError) {
      return null;
    }
    throw error;
  }
}
