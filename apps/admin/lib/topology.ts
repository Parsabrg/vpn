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

export interface VpnServerHealthItem {
  serverId: string;
  code: string;
  state: "healthy" | "degraded" | "unreachable" | "unknown";
  observedAt: string;
  latencyMs: number | null;
  agentVersion: string | null;
  interfaceUp: boolean | null;
  peerCount: number | null;
}

export interface VpnServerReconciliationItem {
  serverId: string;
  code: string;
  pendingProvisions: number;
  pendingRevocations: number;
  failedRecords: number;
}

export interface TrafficSummaryItem {
  protocol: string;
  rxBytes: string;
  txBytes: string;
  totalBytes: string;
  newestCollectedAt: string | null;
}

export async function getTrafficSummary(): Promise<TrafficSummaryItem[]> {
  const body = await apiFetch<{
    items: {
      protocol: string;
      rx_bytes: string;
      tx_bytes: string;
      total_bytes: string;
      newest_collected_at: string | null;
    }[];
  }>("/v1/admin/traffic-summary");
  return body.items.map((item) => ({
    protocol: item.protocol,
    rxBytes: item.rx_bytes,
    txBytes: item.tx_bytes,
    totalBytes: item.total_bytes,
    newestCollectedAt: item.newest_collected_at,
  }));
}

export interface VpnServerXrayHealthItem {
  serverId: string;
  code: string;
  state: VpnServerHealthItem["state"];
  observedAt: string;
  latencyMs: number | null;
  agentVersion: string | null;
  listenerUp: boolean | null;
  errorCode: string | null;
}

export async function getVpnServerXrayHealth(): Promise<
  VpnServerXrayHealthItem[]
> {
  const body = await apiFetch<{
    items: {
      server_id: string;
      code: string;
      state: VpnServerHealthItem["state"];
      observed_at: string;
      latency_ms: number | null;
      agent_version: string | null;
      listener_up: boolean | null;
      error_code: string | null;
    }[];
  }>("/v1/admin/vpn-servers/xray-health");
  return body.items.map((item) => ({
    serverId: item.server_id,
    code: item.code,
    state: item.state,
    observedAt: item.observed_at,
    latencyMs: item.latency_ms,
    agentVersion: item.agent_version,
    listenerUp: item.listener_up,
    errorCode: item.error_code,
  }));
}

export interface ReconciliationHistoryItem {
  id: string;
  serverId: string;
  serverCode: string;
  targetKind: string;
  targetId: string;
  desiredGeneration: number;
  observedGeneration: number | null;
  outcome: string;
  checkedAt: string;
  errorCode: string | null;
}

export interface ReconciliationHistoryPage {
  items: ReconciliationHistoryItem[];
  total: number;
  limit: number;
  offset: number;
}

interface ReconciliationHistoryItemBody {
  id: string;
  server_id: string;
  server_code: string;
  target_kind: string;
  target_id: string;
  desired_generation: number;
  observed_generation: number | null;
  outcome: string;
  checked_at: string;
  error_code: string | null;
}

export async function listReconciliationHistory(query: {
  serverId?: string;
  targetId?: string;
  outcome?: string;
  offset: number;
  limit: number;
}): Promise<ReconciliationHistoryPage> {
  const body = await apiFetch<{
    items: ReconciliationHistoryItemBody[];
    total: number;
    limit: number;
    offset: number;
  }>("/v1/admin/reconciliation-history", {
    searchParams: {
      server_id: query.serverId,
      target_id: query.targetId,
      outcome: query.outcome,
      limit: query.limit,
      offset: query.offset,
    },
  });
  return {
    items: body.items.map((item) => ({
      id: item.id,
      serverId: item.server_id,
      serverCode: item.server_code,
      targetKind: item.target_kind,
      targetId: item.target_id,
      desiredGeneration: item.desired_generation,
      observedGeneration: item.observed_generation,
      outcome: item.outcome,
      checkedAt: item.checked_at,
      errorCode: item.error_code,
    })),
    total: body.total,
    limit: body.limit,
    offset: body.offset,
  };
}

interface VpnServerReconciliationItemBody {
  server_id: string;
  code: string;
  pending_provisions: number;
  pending_revocations: number;
  failed_records: number;
}

export async function getVpnServerReconciliation(): Promise<
  VpnServerReconciliationItem[]
> {
  const body = await apiFetch<{ items: VpnServerReconciliationItemBody[] }>(
    "/v1/admin/vpn-servers/reconciliation",
  );
  return body.items.map((item) => ({
    serverId: item.server_id,
    code: item.code,
    pendingProvisions: item.pending_provisions,
    pendingRevocations: item.pending_revocations,
    failedRecords: item.failed_records,
  }));
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

interface VpnServerHealthItemBody {
  server_id: string;
  code: string;
  state: "healthy" | "degraded" | "unreachable" | "unknown";
  observed_at: string;
  latency_ms: number | null;
  agent_version: string | null;
  interface_up: boolean | null;
  peer_count: number | null;
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

export async function getVpnServerHealth(): Promise<VpnServerHealthItem[]> {
  const body = await apiFetch<{ items: VpnServerHealthItemBody[] }>(
    "/v1/admin/vpn-servers/health",
  );
  return body.items.map((item) => ({
    serverId: item.server_id,
    code: item.code,
    state: item.state,
    observedAt: item.observed_at,
    latencyMs: item.latency_ms,
    agentVersion: item.agent_version,
    interfaceUp: item.interface_up,
    peerCount: item.peer_count,
  }));
}
