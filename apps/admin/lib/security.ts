import { apiFetch } from "@/lib/api/client";

export type CheckStatus = "ok" | "warning" | "failing" | "unknown";

export interface SecurityCheck {
  key: string;
  label: string;
  status: CheckStatus;
  detail: string;
  observedAt: string | null;
}

interface SecurityCheckBody {
  key: string;
  label: string;
  status: CheckStatus;
  detail: string;
  observed_at: string | null;
}

export async function getSecurityStatus(): Promise<SecurityCheck[]> {
  const body = await apiFetch<{ checks: SecurityCheckBody[] }>(
    "/v1/admin/security-status",
  );
  return body.checks.map((check) => ({
    key: check.key,
    label: check.label,
    status: check.status,
    detail: check.detail,
    observedAt: check.observed_at,
  }));
}
