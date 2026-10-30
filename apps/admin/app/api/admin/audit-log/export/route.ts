import { type NextRequest, NextResponse } from "next/server";
import { adminOrigin, apiBaseUrl } from "@/lib/api/config";

/**
 * Downloads the audit log as a hash chain (`nebula-api audit-verify` checks
 * it). The API answers only to the admin session cookie the browser sends.
 */
export async function GET(request: NextRequest) {
  const upstream = await fetch(
    new URL("/v1/admin/audit-log/export", apiBaseUrl()),
    {
      headers: {
        Cookie: request.headers.get("cookie") ?? "",
        Origin: adminOrigin(),
      },
      cache: "no-store",
    },
  );
  const headers = new Headers({
    "Content-Type":
      upstream.headers.get("content-type") ?? "application/x-ndjson",
    "Cache-Control": "no-store",
  });
  const disposition = upstream.headers.get("content-disposition");
  if (upstream.ok && disposition) {
    headers.set("Content-Disposition", disposition);
  }
  return new NextResponse(upstream.body, { status: upstream.status, headers });
}
