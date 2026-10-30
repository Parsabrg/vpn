import "server-only";
import { apiFetch } from "@/lib/api/client";

export interface DevicePairing {
  link: string;
  appLink: string;
  /** The QR code as an image URL, so the markup is never inserted as HTML. */
  qrImage: string;
  deploymentId: string;
  caSha256: string | null;
}

interface AdminPairingResponseBody {
  link: string;
  app_link: string;
  qr_svg: string;
  deployment_id: string;
  ca_sha256: string | null;
}

export function toDevicePairing(body: AdminPairingResponseBody): DevicePairing {
  return {
    link: body.link,
    appLink: body.app_link,
    qrImage: `data:image/svg+xml;base64,${Buffer.from(body.qr_svg, "utf8").toString("base64")}`,
    deploymentId: body.deployment_id,
    caSha256: body.ca_sha256,
  };
}

export async function getDevicePairing(): Promise<DevicePairing> {
  return toDevicePairing(
    await apiFetch<AdminPairingResponseBody>("/v1/admin/pairing"),
  );
}
