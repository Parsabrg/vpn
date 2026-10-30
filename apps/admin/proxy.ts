import { type NextRequest, NextResponse } from "next/server";

/**
 * Content-Security-Policy and Permissions-Policy for every page.
 *
 * A fresh nonce per request, which Next puts on its own scripts; with
 * 'strict-dynamic' those may load the rest, and nothing else runs. The panel
 * has no inline scripts and no third-party origins, so everything else is
 * this origin only. Styles keep 'unsafe-inline' for React's style attributes.
 * The root layout is dynamic so every page is rendered with the nonce.
 */
export function proxy(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const development = process.env.NODE_ENV === "development";
  const policy = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${development ? " 'unsafe-eval'" : ""}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    ...(development ? [] : ["upgrade-insecure-requests"]),
  ].join("; ");

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", policy);
  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", policy);
  response.headers.set(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=(), payment=(), usb=(), " +
      "bluetooth=(), serial=(), hid=(), accelerometer=(), gyroscope=(), " +
      "magnetometer=(), display-capture=(), interest-cohort=()",
  );
  return response;
}

export const config = {
  matcher: [
    {
      source: "/((?!_next/static|_next/image|favicon.ico).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
