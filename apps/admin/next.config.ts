import type { NextConfig } from "next";

// Next's Server Actions CSRF check compares the request's Origin header
// against the Host header it sees -- which, behind a reverse proxy on a
// non-default port, is the proxy's forwarded host, not the port-bearing
// origin the browser actually sent. Without this, every Server Action
// (including admin sign-in) is rejected with "Invalid Server Actions
// request" as soon as the admin's public origin includes a port, e.g.
// `https://panel.example.com:8444`. `allowedOrigins` wants host[:port],
// not a full URL, hence stripping the protocol here.
const adminOrigin = process.env.NEBULA_ADMIN_ORIGIN;
const adminOriginHost = adminOrigin
  ? adminOrigin.replace(/^https?:\/\//, "")
  : undefined;

const nextConfig: NextConfig = {
  output: "standalone",
  poweredByHeader: false,
  reactStrictMode: true,
  ...(adminOriginHost
    ? { experimental: { serverActions: { allowedOrigins: [adminOriginHost] } } }
    : {}),
};

export default nextConfig;
