import "server-only";
import { apiFetch } from "@/lib/api/client";

export interface ProtocolListItem {
  id: string;
  code: string;
  displayName: string;
  engine: string;
  isUserSelectable: boolean;
}

export interface ProtocolProfileListItem {
  id: string;
  protocolId: string;
  code: string;
  version: number;
  displayName: string;
  state: string;
  transport: string | null;
  transportSecurity: string | null;
  requiresUdp: boolean;
  isFullTunnel: boolean;
}

export interface VpnServerListItem {
  id: string;
  code: string;
  displayName: string;
  state: string;
  publicHost: string;
  maximumDevices: number;
}

interface ProtocolListItemBody {
  id: string;
  code: string;
  display_name: string;
  engine: string;
  is_user_selectable: boolean;
}

interface ProtocolProfileListItemBody {
  id: string;
  protocol_id: string;
  code: string;
  version: number;
  display_name: string;
  state: string;
  transport: string | null;
  transport_security: string | null;
  requires_udp: boolean;
  is_full_tunnel: boolean;
}

interface VpnServerListItemBody {
  id: string;
  code: string;
  display_name: string;
  state: string;
  public_host: string;
  maximum_devices: number;
}

export async function listProtocols(): Promise<ProtocolListItem[]> {
  const body = await apiFetch<{ items: ProtocolListItemBody[] }>(
    "/v1/admin/protocols",
  );
  return body.items.map((item) => ({
    id: item.id,
    code: item.code,
    displayName: item.display_name,
    engine: item.engine,
    isUserSelectable: item.is_user_selectable,
  }));
}

export async function listProtocolProfiles(): Promise<
  ProtocolProfileListItem[]
> {
  const body = await apiFetch<{ items: ProtocolProfileListItemBody[] }>(
    "/v1/admin/protocol-profiles",
  );
  return body.items.map((item) => ({
    id: item.id,
    protocolId: item.protocol_id,
    code: item.code,
    version: item.version,
    displayName: item.display_name,
    state: item.state,
    transport: item.transport,
    transportSecurity: item.transport_security,
    requiresUdp: item.requires_udp,
    isFullTunnel: item.is_full_tunnel,
  }));
}

export async function listVpnServers(): Promise<VpnServerListItem[]> {
  const body = await apiFetch<{ items: VpnServerListItemBody[] }>(
    "/v1/admin/vpn-servers",
  );
  return body.items.map((item) => ({
    id: item.id,
    code: item.code,
    displayName: item.display_name,
    state: item.state,
    publicHost: item.public_host,
    maximumDevices: item.maximum_devices,
  }));
}
