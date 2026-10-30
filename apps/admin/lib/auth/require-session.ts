import "server-only";
import { redirect } from "next/navigation";
import { getAdminSession } from "./session";
import type { AdminSession } from "./types";

/** Redirects to `/login?reason=expired` when there is no valid admin session. */
export async function requireAdminSession(): Promise<AdminSession> {
  const session = await getAdminSession();
  if (session === null) {
    redirect("/login?reason=expired");
  }
  return session;
}
