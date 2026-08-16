import type { NextRequest } from "next/server";
import { proxyAdminAuthRequest } from "@/lib/api/auth-proxy";

export async function POST(request: NextRequest) {
  return proxyAdminAuthRequest(request, "/v1/admin/auth/step-up");
}
