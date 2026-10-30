export const dynamic = "force-static";

export function GET() {
  return Response.json({
    service: "nebula-admin",
    status: "ok",
    capabilities: {
      authentication: false,
      controlPlane: false,
      vpnManagement: false,
    },
  });
}
