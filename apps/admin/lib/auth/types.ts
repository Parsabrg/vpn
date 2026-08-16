export type AdminRole = "owner" | "operator" | "auditor";

export interface AdminSession {
  adminId: string;
  role: AdminRole;
  stepUp: boolean;
}
