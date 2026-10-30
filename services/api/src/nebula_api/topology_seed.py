"""Transactional CLI seed commands for VPN topology: the WireGuard protocol
profile, VPN servers, and per-user permission/assignment grants.

Follows seed_admin.py's shape exactly: a transaction-scoped advisory lock for
uniqueness-sensitive creation, session_scope for commit/rollback, and audit
events written in the same transaction as the mutation they describe.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID

from sqlalchemy import select, text

from nebula_api.db.engine import SessionFactory, session_scope
from nebula_api.identity import normalize_email
from nebula_api.models.identity import User
from nebula_api.models.operations import AuditLog
from nebula_api.models.topology import (
    Protocol,
    ProtocolProfile,
    ServerProtocolCapability,
    UserProtocolPermission,
    UserServerAssignment,
    VPNServer,
)
from nebula_api.models.types import CapabilityState, LifecycleState, ProfileState, ProtocolEngine

WIREGUARD_PROTOCOL_CODE = "wireguard"
WIREGUARD_PROFILE_CODE = "wireguard-native"
WIREGUARD_PROFILE_DISPLAY_NAME = "WireGuard"
WIREGUARD_PROFILE_VERSION = 1

VLESS_PROTOCOL_CODE = "vless"
VLESS_PROFILE_CODE = "vless-xhttp-tls"
VLESS_PROFILE_DISPLAY_NAME = "VLESS (XHTTP+TLS)"
VLESS_PROFILE_VERSION = 1
VLESS_REQUIRED_PORT = 8445

# The other three VLESS transports share the same "vless" Protocol row as
# XHTTP above (one Protocol per client-facing protocol code, not per
# transport) -- each gets its own ProtocolProfile row instead. Unlike XHTTP
# (nginx-fronted, loopback-only), Xray terminates TLS directly and binds
# these publicly, so each profile's required_port is the agent's own public
# listener port (matches services/vpn-agent's settings.py defaults).
VLESS_GRPC_PROFILE_CODE = "vless-grpc-tls"
VLESS_GRPC_PROFILE_DISPLAY_NAME = "VLESS (gRPC+TLS)"
VLESS_GRPC_REQUIRED_PORT = 8447

VLESS_WS_PROFILE_CODE = "vless-ws-tls"
VLESS_WS_PROFILE_DISPLAY_NAME = "VLESS (WebSocket+TLS)"
VLESS_WS_REQUIRED_PORT = 8448

VLESS_TCP_PROFILE_CODE = "vless-tcp-tls"
VLESS_TCP_PROFILE_DISPLAY_NAME = "VLESS (raw TCP+TLS)"
VLESS_TCP_REQUIRED_PORT = 8449

# Hysteria2 is its own Protocol (own client-facing protocol code, own
# top-level `Protocol.engine = 'xray'` row per the code_engine_pair CHECK
# constraint) -- Xray-core's own native `protocol: "hysteria"` inbound, not
# a distinct engine, so no schema change was needed to add it. Runs over
# QUIC/UDP, unlike every other profile here.
HYSTERIA2_PROTOCOL_CODE = "hysteria2"
HYSTERIA2_PROFILE_CODE = "hysteria2"
HYSTERIA2_PROFILE_DISPLAY_NAME = "Hysteria2"
HYSTERIA2_REQUIRED_PORT = 8450

# Shadowsocks-2022: its own Protocol, served by Xray on a raw TCP+UDP port
# with no TLS. Its traffic looks random, which Iran let through to the very
# address whose TLS it stalls (home line, 2026-10-22).
SHADOWSOCKS_PROTOCOL_CODE = "shadowsocks"
SS2022_PROFILE_CODE = "shadowsocks-2022"
SS2022_PROFILE_DISPLAY_NAME = "Shadowsocks-2022"
SS2022_REQUIRED_PORT = 8451

# Two more profiles with their own encryption and no TLS, dialled directly
# like Shadowsocks-2022: VLESS Encryption (53 Mbit/s from the home line) and
# VMess raw / WebSocket (39-47 Mbit/s), 2026-10-22. Not on mobile data.
VLESSENC_PROFILE_CODE = "vless-enc"
VLESSENC_REQUIRED_PORT = 8453
VMESS_PROTOCOL_CODE = "vmess"
VMESS_RAW_PROFILE_CODE = "vmess-raw"
VMESS_RAW_REQUIRED_PORT = 8454
VMESS_WS_PROFILE_CODE = "vmess-ws"
VMESS_WS_REQUIRED_PORT = 8455

# Every connection profile gets a manually-selectable ad-block sibling,
# picked from the same server-listing picker as the "regular" one -- not a
# per-device toggle. The suffix is appended to the base profile's own code.
_AD_BLOCK_SUFFIX = "-adblock"
WIREGUARD_ADBLOCK_PROFILE_CODE = WIREGUARD_PROFILE_CODE + _AD_BLOCK_SUFFIX


class SeedProtocolStatus(StrEnum):
    CREATED = "created"
    ALREADY_SEEDED = "already_seeded"


@dataclass(frozen=True, slots=True)
class SeedProtocolResult:
    status: SeedProtocolStatus
    protocol_id: UUID
    protocol_profile_id: UUID


async def seed_wireguard_protocol(session_factory: SessionFactory) -> SeedProtocolResult:
    """Idempotent: creates the canonical WireGuard Protocol + implemented
    ProtocolProfile if absent, otherwise returns the existing ids. Run once
    ever. The Protocol row may later gain a second profile
    (`WIREGUARD_ADBLOCK_PROFILE_CODE`, see seed_wireguard_adblock_profile)
    -- the "already seeded" lookup below is scoped to this function's own
    profile code, not "the protocol's one profile", so it stays correct
    once that second profile exists."""

    async with session_scope(session_factory) as session:
        await session.execute(
            text("SELECT pg_advisory_xact_lock(hashtext('nebula.wireguard_protocol_seed'))")
        )
        protocol = await session.scalar(
            select(Protocol).where(Protocol.code == WIREGUARD_PROTOCOL_CODE)
        )
        if protocol is not None:
            profile = await session.scalar(
                select(ProtocolProfile).where(
                    ProtocolProfile.protocol_id == protocol.id,
                    ProtocolProfile.code == WIREGUARD_PROFILE_CODE,
                )
            )
            if profile is None:
                raise ValueError(
                    "a 'wireguard' protocol row exists without a profile; this needs manual repair"
                )
            return SeedProtocolResult(
                status=SeedProtocolStatus.ALREADY_SEEDED,
                protocol_id=protocol.id,
                protocol_profile_id=profile.id,
            )

        protocol = Protocol(
            code=WIREGUARD_PROTOCOL_CODE,
            display_name="WireGuard",
            engine=ProtocolEngine.NATIVE_WIREGUARD.value,
            is_user_selectable=True,
        )
        session.add(protocol)
        await session.flush()

        profile = ProtocolProfile(
            protocol_id=protocol.id,
            code=WIREGUARD_PROFILE_CODE,
            version=WIREGUARD_PROFILE_VERSION,
            display_name=WIREGUARD_PROFILE_DISPLAY_NAME,
            state=ProfileState.IMPLEMENTED.value,
            requires_udp=True,
            is_full_tunnel=True,
        )
        session.add(profile)
        await session.flush()

        session.add(
            AuditLog(
                actor_kind="bootstrap",
                actor_id=None,
                target_kind="protocol_profile",
                target_id=profile.id,
                event_code="profile_changed",
                outcome="succeeded",
                request_id=None,
                correlation_id=None,
                reason_code="seeded",
            )
        )
        return SeedProtocolResult(
            status=SeedProtocolStatus.CREATED,
            protocol_id=protocol.id,
            protocol_profile_id=profile.id,
        )


async def _seed_xray_protocol_profile(
    session_factory: SessionFactory,
    *,
    lock_key: str,
    protocol_code: str,
    protocol_display_name: str,
    profile_code: str,
    profile_version: int,
    profile_display_name: str,
    transport: str,
    required_port: int,
    requires_udp: bool,
    ad_block: bool = False,
    agent_profile_code: str | None = None,
    engine: ProtocolEngine = ProtocolEngine.XRAY,
    transport_security: str | None = "tls",
) -> SeedProtocolResult:
    """Idempotent: get-or-create the Protocol row, then get-or-create the
    named ProtocolProfile row under it.

    `engine` names what actually serves the protocol, and models/topology.py's
    code_engine_pair CHECK constraint pins each code to one. It defaults to
    Xray because most codes here are Xray transports; Hysteria2 passes
    HYSTERIA, since Xray accepts its obfuscation setting and silently discards
    it (docs/adr/0003) and it runs on the reference binary instead.

    Unlike seed_wireguard_protocol (exactly one profile, ever), a Protocol
    here can own several ProtocolProfile rows -- e.g. "vless" owns one per
    transport (XHTTP, gRPC, WebSocket, raw TCP), each with its own ad_block
    sibling -- so profile lookup is scoped to `profile_code`, not "the
    protocol's one profile"."""

    async with session_scope(session_factory) as session:
        await session.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:lock_key))"), {"lock_key": lock_key}
        )
        protocol = await session.scalar(select(Protocol).where(Protocol.code == protocol_code))
        if protocol is None:
            protocol = Protocol(
                code=protocol_code,
                display_name=protocol_display_name,
                engine=engine.value,
                is_user_selectable=True,
            )
            session.add(protocol)
            await session.flush()

        profile = await session.scalar(
            select(ProtocolProfile).where(
                ProtocolProfile.protocol_id == protocol.id,
                ProtocolProfile.code == profile_code,
            )
        )
        if profile is not None:
            return SeedProtocolResult(
                status=SeedProtocolStatus.ALREADY_SEEDED,
                protocol_id=protocol.id,
                protocol_profile_id=profile.id,
            )

        profile = ProtocolProfile(
            protocol_id=protocol.id,
            code=profile_code,
            version=profile_version,
            display_name=profile_display_name,
            state=ProfileState.IMPLEMENTED.value,
            transport=transport,
            transport_security=transport_security,
            template_key=profile_code.replace("-", "_"),
            required_port=required_port,
            requires_udp=requires_udp,
            is_full_tunnel=True,
            ad_block=ad_block,
            agent_profile_code=agent_profile_code,
        )
        session.add(profile)
        await session.flush()

        session.add(
            AuditLog(
                actor_kind="bootstrap",
                actor_id=None,
                target_kind="protocol_profile",
                target_id=profile.id,
                event_code="profile_changed",
                outcome="succeeded",
                request_id=None,
                correlation_id=None,
                reason_code="seeded",
            )
        )
        return SeedProtocolResult(
            status=SeedProtocolStatus.CREATED,
            protocol_id=protocol.id,
            protocol_profile_id=profile.id,
        )


async def seed_vless_xhttp_protocol(session_factory: SessionFactory) -> SeedProtocolResult:
    """Idempotent: creates the canonical VLESS-over-XHTTP+TLS Protocol + implemented
    ProtocolProfile if absent, otherwise returns the existing ids. Run once ever."""

    return await _seed_xray_protocol_profile(
        session_factory,
        lock_key="nebula.vless_xhttp_protocol_seed",
        protocol_code=VLESS_PROTOCOL_CODE,
        protocol_display_name="VLESS",
        profile_code=VLESS_PROFILE_CODE,
        profile_version=VLESS_PROFILE_VERSION,
        profile_display_name=VLESS_PROFILE_DISPLAY_NAME,
        transport="xhttp",
        required_port=VLESS_REQUIRED_PORT,
        requires_udp=False,
    )


async def seed_vless_xhttp_adblock_protocol(session_factory: SessionFactory) -> SeedProtocolResult:
    """Idempotent: adds the ad-blocking sibling of VLESS-over-XHTTP+TLS --
    a separate, manually-selectable profile, not a per-device toggle.
    `agent_profile_code` points at the real profile the agent inbound is
    configured under, since the agent has no concept of ad-block variants
    itself. Run once ever."""

    return await _seed_xray_protocol_profile(
        session_factory,
        lock_key="nebula.vless_xhttp_adblock_protocol_seed",
        protocol_code=VLESS_PROTOCOL_CODE,
        protocol_display_name="VLESS",
        profile_code=VLESS_PROFILE_CODE + _AD_BLOCK_SUFFIX,
        profile_version=1,
        profile_display_name=VLESS_PROFILE_DISPLAY_NAME + " (Ad-block)",
        transport="xhttp",
        required_port=VLESS_REQUIRED_PORT,
        requires_udp=False,
        ad_block=True,
        agent_profile_code=VLESS_PROFILE_CODE,
    )


async def seed_vless_grpc_protocol(session_factory: SessionFactory) -> SeedProtocolResult:
    """Idempotent: adds the VLESS-over-gRPC+TLS profile to the (possibly
    already-seeded) "vless" Protocol row. Run once ever."""

    return await _seed_xray_protocol_profile(
        session_factory,
        lock_key="nebula.vless_grpc_protocol_seed",
        protocol_code=VLESS_PROTOCOL_CODE,
        protocol_display_name="VLESS",
        profile_code=VLESS_GRPC_PROFILE_CODE,
        profile_version=1,
        profile_display_name=VLESS_GRPC_PROFILE_DISPLAY_NAME,
        transport="grpc",
        required_port=VLESS_GRPC_REQUIRED_PORT,
        requires_udp=False,
    )


async def seed_vless_grpc_adblock_protocol(session_factory: SessionFactory) -> SeedProtocolResult:
    """Idempotent: adds the ad-blocking sibling of VLESS-over-gRPC+TLS.
    Run once ever."""

    return await _seed_xray_protocol_profile(
        session_factory,
        lock_key="nebula.vless_grpc_adblock_protocol_seed",
        protocol_code=VLESS_PROTOCOL_CODE,
        protocol_display_name="VLESS",
        profile_code=VLESS_GRPC_PROFILE_CODE + _AD_BLOCK_SUFFIX,
        profile_version=1,
        profile_display_name=VLESS_GRPC_PROFILE_DISPLAY_NAME + " (Ad-block)",
        transport="grpc",
        required_port=VLESS_GRPC_REQUIRED_PORT,
        requires_udp=False,
        ad_block=True,
        agent_profile_code=VLESS_GRPC_PROFILE_CODE,
    )


async def seed_vless_ws_protocol(session_factory: SessionFactory) -> SeedProtocolResult:
    """Idempotent: adds the VLESS-over-WebSocket+TLS profile to the
    (possibly already-seeded) "vless" Protocol row. Run once ever."""

    return await _seed_xray_protocol_profile(
        session_factory,
        lock_key="nebula.vless_ws_protocol_seed",
        protocol_code=VLESS_PROTOCOL_CODE,
        protocol_display_name="VLESS",
        profile_code=VLESS_WS_PROFILE_CODE,
        profile_version=1,
        profile_display_name=VLESS_WS_PROFILE_DISPLAY_NAME,
        transport="websocket",
        required_port=VLESS_WS_REQUIRED_PORT,
        requires_udp=False,
    )


async def seed_vless_ws_adblock_protocol(session_factory: SessionFactory) -> SeedProtocolResult:
    """Idempotent: adds the ad-blocking sibling of VLESS-over-WebSocket+TLS.
    Run once ever."""

    return await _seed_xray_protocol_profile(
        session_factory,
        lock_key="nebula.vless_ws_adblock_protocol_seed",
        protocol_code=VLESS_PROTOCOL_CODE,
        protocol_display_name="VLESS",
        profile_code=VLESS_WS_PROFILE_CODE + _AD_BLOCK_SUFFIX,
        profile_version=1,
        profile_display_name=VLESS_WS_PROFILE_DISPLAY_NAME + " (Ad-block)",
        transport="websocket",
        required_port=VLESS_WS_REQUIRED_PORT,
        requires_udp=False,
        ad_block=True,
        agent_profile_code=VLESS_WS_PROFILE_CODE,
    )


async def seed_vless_tcp_protocol(session_factory: SessionFactory) -> SeedProtocolResult:
    """Idempotent: adds the VLESS-over-raw-TCP+TLS profile to the (possibly
    already-seeded) "vless" Protocol row. Run once ever."""

    return await _seed_xray_protocol_profile(
        session_factory,
        lock_key="nebula.vless_tcp_protocol_seed",
        protocol_code=VLESS_PROTOCOL_CODE,
        protocol_display_name="VLESS",
        profile_code=VLESS_TCP_PROFILE_CODE,
        profile_version=1,
        profile_display_name=VLESS_TCP_PROFILE_DISPLAY_NAME,
        transport="raw",
        required_port=VLESS_TCP_REQUIRED_PORT,
        requires_udp=False,
    )


async def seed_vless_tcp_adblock_protocol(session_factory: SessionFactory) -> SeedProtocolResult:
    """Idempotent: adds the ad-blocking sibling of VLESS-over-raw-TCP+TLS.
    Run once ever."""

    return await _seed_xray_protocol_profile(
        session_factory,
        lock_key="nebula.vless_tcp_adblock_protocol_seed",
        protocol_code=VLESS_PROTOCOL_CODE,
        protocol_display_name="VLESS",
        profile_code=VLESS_TCP_PROFILE_CODE + _AD_BLOCK_SUFFIX,
        profile_version=1,
        profile_display_name=VLESS_TCP_PROFILE_DISPLAY_NAME + " (Ad-block)",
        transport="raw",
        required_port=VLESS_TCP_REQUIRED_PORT,
        requires_udp=False,
        ad_block=True,
        agent_profile_code=VLESS_TCP_PROFILE_CODE,
    )


async def seed_hysteria2_protocol(session_factory: SessionFactory) -> SeedProtocolResult:
    """Idempotent: creates the canonical Hysteria2 Protocol + implemented
    ProtocolProfile if absent, otherwise returns the existing ids. Run once
    ever. Hysteria2 runs over QUIC/UDP -- requires_udp=True, unlike every
    other Xray transport here."""

    return await _seed_xray_protocol_profile(
        session_factory,
        lock_key="nebula.hysteria2_protocol_seed",
        protocol_code=HYSTERIA2_PROTOCOL_CODE,
        protocol_display_name="Hysteria2",
        profile_code=HYSTERIA2_PROFILE_CODE,
        profile_version=1,
        profile_display_name=HYSTERIA2_PROFILE_DISPLAY_NAME,
        transport="hysteria",
        required_port=HYSTERIA2_REQUIRED_PORT,
        requires_udp=True,
        engine=ProtocolEngine.HYSTERIA,
    )


async def seed_hysteria2_adblock_protocol(session_factory: SessionFactory) -> SeedProtocolResult:
    """Idempotent: adds the ad-blocking sibling of Hysteria2. Run once ever."""

    return await _seed_xray_protocol_profile(
        session_factory,
        lock_key="nebula.hysteria2_adblock_protocol_seed",
        protocol_code=HYSTERIA2_PROTOCOL_CODE,
        protocol_display_name="Hysteria2",
        profile_code=HYSTERIA2_PROFILE_CODE + _AD_BLOCK_SUFFIX,
        profile_version=1,
        profile_display_name=HYSTERIA2_PROFILE_DISPLAY_NAME + " (Ad-block)",
        transport="hysteria",
        required_port=HYSTERIA2_REQUIRED_PORT,
        requires_udp=True,
        ad_block=True,
        agent_profile_code=HYSTERIA2_PROFILE_CODE,
        engine=ProtocolEngine.HYSTERIA,
    )


async def seed_ss2022_protocol(session_factory: SessionFactory) -> SeedProtocolResult:
    """Idempotent: creates the Shadowsocks Protocol and its 2022 profile.
    No TLS (`transport_security` NULL): Shadowsocks-2022 is its own
    encryption. Run once ever."""

    return await _seed_xray_protocol_profile(
        session_factory,
        lock_key="nebula.ss2022_protocol_seed",
        protocol_code=SHADOWSOCKS_PROTOCOL_CODE,
        protocol_display_name="Shadowsocks",
        profile_code=SS2022_PROFILE_CODE,
        profile_version=1,
        profile_display_name=SS2022_PROFILE_DISPLAY_NAME,
        transport="raw",
        required_port=SS2022_REQUIRED_PORT,
        requires_udp=False,
        transport_security=None,
    )


async def seed_ss2022_adblock_protocol(session_factory: SessionFactory) -> SeedProtocolResult:
    """Idempotent: adds the ad-blocking sibling of Shadowsocks-2022."""

    return await _seed_xray_protocol_profile(
        session_factory,
        lock_key="nebula.ss2022_adblock_protocol_seed",
        protocol_code=SHADOWSOCKS_PROTOCOL_CODE,
        protocol_display_name="Shadowsocks",
        profile_code=SS2022_PROFILE_CODE + _AD_BLOCK_SUFFIX,
        profile_version=1,
        profile_display_name=SS2022_PROFILE_DISPLAY_NAME + " (Ad-block)",
        transport="raw",
        required_port=SS2022_REQUIRED_PORT,
        requires_udp=False,
        ad_block=True,
        agent_profile_code=SS2022_PROFILE_CODE,
        transport_security=None,
    )


async def seed_direct_protocols(
    session_factory: SessionFactory,
) -> list[tuple[str, SeedProtocolResult]]:
    """Idempotent: VLESS Encryption, VMess raw and VMess WebSocket, each with
    its ad-blocking sibling. No TLS (`transport_security` NULL)."""

    specs = (
        (
            VLESS_PROTOCOL_CODE,
            "VLESS",
            VLESSENC_PROFILE_CODE,
            "VLESS Encryption",
            "raw",
            VLESSENC_REQUIRED_PORT,
        ),
        (
            VMESS_PROTOCOL_CODE,
            "VMess",
            VMESS_RAW_PROFILE_CODE,
            "VMess (raw TCP)",
            "raw",
            VMESS_RAW_REQUIRED_PORT,
        ),
        (
            VMESS_PROTOCOL_CODE,
            "VMess",
            VMESS_WS_PROFILE_CODE,
            "VMess (WebSocket)",
            "websocket",
            VMESS_WS_REQUIRED_PORT,
        ),
    )
    results = []
    for protocol_code, protocol_name, code, name, transport, port in specs:
        for ad_block in (False, True):
            profile_code = code + _AD_BLOCK_SUFFIX if ad_block else code
            result = await _seed_xray_protocol_profile(
                session_factory,
                lock_key=f"nebula.{profile_code}_protocol_seed",
                protocol_code=protocol_code,
                protocol_display_name=protocol_name,
                profile_code=profile_code,
                profile_version=1,
                profile_display_name=name + (" (Ad-block)" if ad_block else ""),
                transport=transport,
                required_port=port,
                requires_udp=False,
                ad_block=ad_block,
                agent_profile_code=code if ad_block else None,
                transport_security=None,
            )
            results.append((profile_code, result))
    return results


async def seed_wireguard_adblock_profile(session_factory: SessionFactory) -> SeedProtocolResult:
    """Idempotent: adds the ad-blocking sibling of the canonical WireGuard
    profile to the (already-seeded) "wireguard" Protocol row. Unlike the
    Xray siblings above, this needs no `agent_profile_code` redirect at all
    -- WireGuard has no per-profile agent inbound to redirect (one server
    interface serves every peer regardless of profile); the ad_block flag
    only ever changes which DNS server provisioning/service.py hands back
    in the client config, a purely API-side decision. Requires
    seed_wireguard_protocol to have already run -- run once ever."""

    async with session_scope(session_factory) as session:
        await session.execute(
            text("SELECT pg_advisory_xact_lock(hashtext('nebula.wireguard_adblock_profile_seed'))")
        )
        protocol = await session.scalar(
            select(Protocol).where(Protocol.code == WIREGUARD_PROTOCOL_CODE)
        )
        if protocol is None:
            raise ValueError(
                "no WireGuard protocol is seeded; run `nebula-api seed-wireguard-protocol` first"
            )

        profile = await session.scalar(
            select(ProtocolProfile).where(
                ProtocolProfile.protocol_id == protocol.id,
                ProtocolProfile.code == WIREGUARD_ADBLOCK_PROFILE_CODE,
            )
        )
        if profile is not None:
            return SeedProtocolResult(
                status=SeedProtocolStatus.ALREADY_SEEDED,
                protocol_id=protocol.id,
                protocol_profile_id=profile.id,
            )

        profile = ProtocolProfile(
            protocol_id=protocol.id,
            code=WIREGUARD_ADBLOCK_PROFILE_CODE,
            version=WIREGUARD_PROFILE_VERSION,
            display_name=WIREGUARD_PROFILE_DISPLAY_NAME + " (Ad-block)",
            state=ProfileState.IMPLEMENTED.value,
            # Gives this profile a distinct reviewed tuple from the base
            # WireGuard profile (transport/transport_security/flow are all
            # NULL for both, and uq_protocol_profiles_reviewed_tuple treats
            # NULLs as equal) -- without this they'd collide.
            template_key="wireguard_adblock",
            requires_udp=True,
            is_full_tunnel=True,
            ad_block=True,
        )
        session.add(profile)
        await session.flush()

        session.add(
            AuditLog(
                actor_kind="bootstrap",
                actor_id=None,
                target_kind="protocol_profile",
                target_id=profile.id,
                event_code="profile_changed",
                outcome="succeeded",
                request_id=None,
                correlation_id=None,
                reason_code="seeded",
            )
        )
        return SeedProtocolResult(
            status=SeedProtocolStatus.CREATED,
            protocol_id=protocol.id,
            protocol_profile_id=profile.id,
        )


class CreateServerStatus(StrEnum):
    CREATED = "created"


@dataclass(frozen=True, slots=True)
class CreateServerResult:
    status: CreateServerStatus
    vpn_server_id: UUID


async def create_vpn_server(
    session_factory: SessionFactory,
    *,
    code: str,
    display_name: str,
    agent_host: str,
    agent_port: int,
    public_host: str,
    wireguard_client_pool: str | None,
    wireguard_gateway_address: str | None,
    maximum_devices: int,
    state: str,
) -> CreateServerResult:
    """Creates the VPNServer row and auto-enables its WireGuard
    ServerProtocolCapability in the same transaction -- Phase 1 only ever
    has one protocol, so this collapses two admin concerns into one
    command. Requires seed_wireguard_protocol to have already run. Rejects
    a duplicate code outright rather than silently succeeding -- a typo is
    more likely than an intentional re-run."""

    async with session_scope(session_factory) as session:
        await session.execute(
            text(
                "SELECT pg_advisory_xact_lock("
                "hashtext('nebula.vpn_server_create'), hashtext(:code))"
            ),
            {"code": code},
        )
        existing = await session.scalar(select(VPNServer).where(VPNServer.code == code))
        if existing is not None:
            raise ValueError(f"a VPN server with code {code!r} already exists")

        protocol = await session.scalar(
            select(Protocol).where(Protocol.code == WIREGUARD_PROTOCOL_CODE)
        )
        if protocol is None:
            raise ValueError(
                "no WireGuard protocol is seeded; run `nebula-api seed-wireguard-protocol` first"
            )
        profile = await session.scalar(
            select(ProtocolProfile).where(
                ProtocolProfile.protocol_id == protocol.id,
                ProtocolProfile.state == ProfileState.IMPLEMENTED.value,
            )
        )
        if profile is None:
            raise ValueError(
                "no implemented WireGuard protocol profile found; "
                "run `nebula-api seed-wireguard-protocol` first"
            )

        server = VPNServer(
            code=code,
            display_name=display_name,
            state=state,
            agent_host=agent_host,
            agent_port=agent_port,
            public_host=public_host,
            wireguard_client_pool=wireguard_client_pool,
            wireguard_gateway_address=wireguard_gateway_address,
            maximum_devices=maximum_devices,
        )
        session.add(server)
        await session.flush()

        capability = ServerProtocolCapability(
            vpn_server_id=server.id,
            protocol_profile_id=profile.id,
            state=CapabilityState.ENABLED.value,
            validated_profile_version=str(profile.version),
        )
        session.add(capability)
        await session.flush()

        session.add(
            AuditLog(
                actor_kind="bootstrap",
                actor_id=None,
                target_kind="vpn_server",
                target_id=server.id,
                event_code="server_changed",
                outcome="succeeded",
                request_id=None,
                correlation_id=None,
                reason_code="created",
            )
        )
        session.add(
            AuditLog(
                actor_kind="bootstrap",
                actor_id=None,
                target_kind="server_capability",
                target_id=capability.id,
                event_code="capability_changed",
                outcome="succeeded",
                request_id=None,
                correlation_id=None,
                reason_code="enabled",
            )
        )
        return CreateServerResult(status=CreateServerStatus.CREATED, vpn_server_id=server.id)


class EnableCapabilityStatus(StrEnum):
    CREATED = "created"
    ALREADY_ENABLED = "already_enabled"
    RE_ENABLED = "re_enabled"


@dataclass(frozen=True, slots=True)
class EnableCapabilityResult:
    status: EnableCapabilityStatus
    server_protocol_capability_id: UUID


async def disable_server_capability(
    session_factory: SessionFactory,
    *,
    server_code: str,
    protocol_profile_code: str,
) -> bool:
    """Stops offering a protocol profile on a server; true if it was offered.

    For a protocol turned off on the server itself (install.sh --configure):
    left enabled here, clients would be handed an endpoint nothing answers.
    Credentials already issued for it are not touched; reconciliation and
    their devices' next request take care of those."""

    async with session_scope(session_factory) as session:
        capability = await session.scalar(
            select(ServerProtocolCapability)
            .join(VPNServer, VPNServer.id == ServerProtocolCapability.vpn_server_id)
            .join(
                ProtocolProfile, ProtocolProfile.id == ServerProtocolCapability.protocol_profile_id
            )
            .where(
                VPNServer.code == server_code,
                ProtocolProfile.code == protocol_profile_code,
                ServerProtocolCapability.state == CapabilityState.ENABLED.value,
            )
        )
        if capability is None:
            return False
        capability.state = CapabilityState.DISABLED.value
        return True


async def enable_server_capability(
    session_factory: SessionFactory,
    *,
    server_code: str,
    protocol_profile_code: str,
) -> EnableCapabilityResult:
    """Enables an additional protocol profile on an already-existing VPN
    server -- the gap create_vpn_server always left, since it only ever
    auto-enables WireGuard. Every new Xray transport (gRPC/WS/TCP/Hysteria2)
    needs exactly this to actually become usable on a real, already-running
    server, so this is a general-purpose "turn on profile X on server Y"
    command rather than another one-off per transport. Idempotent: creates
    the ServerProtocolCapability row if absent, re-enables it if it exists
    but was previously disabled, and is a no-op if it's already enabled."""

    async with session_scope(session_factory) as session:
        await session.execute(
            text(
                "SELECT pg_advisory_xact_lock("
                "hashtext('nebula.enable_server_capability'), hashtext(:key))"
            ),
            {"key": f"{server_code}:{protocol_profile_code}"},
        )

        server = await session.scalar(select(VPNServer).where(VPNServer.code == server_code))
        if server is None:
            raise ValueError(f"no VPN server found with code {server_code!r}")

        profile = await session.scalar(
            select(ProtocolProfile).where(ProtocolProfile.code == protocol_profile_code)
        )
        if profile is None or profile.state != ProfileState.IMPLEMENTED.value:
            raise ValueError(
                f"no implemented protocol profile found with code {protocol_profile_code!r}; "
                "run the matching seed command first"
            )

        capability = await session.scalar(
            select(ServerProtocolCapability).where(
                ServerProtocolCapability.vpn_server_id == server.id,
                ServerProtocolCapability.protocol_profile_id == profile.id,
            )
        )
        if capability is not None and capability.state == CapabilityState.ENABLED.value:
            return EnableCapabilityResult(
                status=EnableCapabilityStatus.ALREADY_ENABLED,
                server_protocol_capability_id=capability.id,
            )

        if capability is None:
            capability = ServerProtocolCapability(
                vpn_server_id=server.id,
                protocol_profile_id=profile.id,
                state=CapabilityState.ENABLED.value,
                validated_profile_version=str(profile.version),
            )
            session.add(capability)
            status = EnableCapabilityStatus.CREATED
        else:
            capability.state = CapabilityState.ENABLED.value
            status = EnableCapabilityStatus.RE_ENABLED
        await session.flush()

        session.add(
            AuditLog(
                actor_kind="bootstrap",
                actor_id=None,
                target_kind="server_capability",
                target_id=capability.id,
                event_code="capability_changed",
                outcome="succeeded",
                request_id=None,
                correlation_id=None,
                reason_code="enabled",
            )
        )
        return EnableCapabilityResult(status=status, server_protocol_capability_id=capability.id)


class GrantAccessStatus(StrEnum):
    GRANTED = "granted"


@dataclass(frozen=True, slots=True)
class GrantAccessResult:
    status: GrantAccessStatus
    user_id: UUID
    # What the account can actually use afterwards. Reported rather than
    # implied: "granted access" meant one profile out of twelve for a long
    # time, and nothing said so.
    profile_codes: list[str] = field(default_factory=list)


async def grant_user_server_access(
    session_factory: SessionFactory,
    *,
    user_email: str,
    server_code: str,
) -> GrantAccessResult:
    """Give a user every protocol this server offers, and the server itself.

    One transaction, and idempotent: a disabled or revoked row is reactivated
    rather than erroring, so running it twice is a no-op.

    It used to grant the WireGuard profile alone, which meant every other
    protocol needed hand-written SQL before the account could use it.
    """

    normalized_email = normalize_email(user_email)

    async with session_scope(session_factory) as session:
        await session.execute(
            text(
                "SELECT pg_advisory_xact_lock(hashtext('nebula.grant_user_access'), hashtext(:key))"
            ),
            {"key": f"{normalized_email}:{server_code}"},
        )

        user = await session.scalar(select(User).where(User.email_normalized == normalized_email))
        if user is None:
            raise ValueError(f"no user found with email {user_email!r}")

        server = await session.scalar(select(VPNServer).where(VPNServer.code == server_code))
        if server is None:
            raise ValueError(f"no VPN server found with code {server_code!r}")

        # Every profile this server actually offers, not just WireGuard.
        #
        # Granting one meant every other protocol needed hand-written SQL
        # before the account could use it, and nothing said so: the user saw
        # the server in the picker and was refused by eleven of the twelve
        # protocols on it. Reading the server's own capabilities is also the
        # only definition that stays correct as protocols are added.
        profiles = (
            await session.scalars(
                select(ProtocolProfile)
                .join(
                    ServerProtocolCapability,
                    ServerProtocolCapability.protocol_profile_id == ProtocolProfile.id,
                )
                .where(
                    ServerProtocolCapability.vpn_server_id == server.id,
                    ServerProtocolCapability.state == CapabilityState.ENABLED.value,
                    ProtocolProfile.state == ProfileState.IMPLEMENTED.value,
                )
                .order_by(ProtocolProfile.code)
            )
        ).all()
        if not profiles:
            raise ValueError(
                f"server {server_code!r} has no enabled protocol capabilities; "
                "seed the protocols and run `nebula-api enable-server-capability` first"
            )

        now = datetime.now(UTC)

        granted: list[str] = []
        for profile in profiles:
            permission = await session.scalar(
                select(UserProtocolPermission).where(
                    UserProtocolPermission.user_id == user.id,
                    UserProtocolPermission.protocol_profile_id == profile.id,
                )
            )
            if permission is None:
                permission = UserProtocolPermission(
                    user_id=user.id,
                    protocol_profile_id=profile.id,
                    granted_by_admin_id=None,
                    state=CapabilityState.ENABLED.value,
                    granted_at=now,
                )
                session.add(permission)
            elif permission.state != CapabilityState.ENABLED.value:
                permission.state = CapabilityState.ENABLED.value
                permission.granted_at = now
                permission.revoked_at = None
            granted.append(profile.code)
            await session.flush()
            # One event per grant rather than one for the batch: an audit
            # trail that records "access granted" once for twelve profiles
            # cannot answer which of them somebody was given.
            session.add(
                AuditLog(
                    actor_kind="bootstrap",
                    actor_id=None,
                    target_kind="permission",
                    target_id=permission.id,
                    event_code="permission_changed",
                    outcome="succeeded",
                    request_id=None,
                    correlation_id=None,
                    reason_code="granted",
                )
            )

        assignment = await session.scalar(
            select(UserServerAssignment).where(
                UserServerAssignment.user_id == user.id,
                UserServerAssignment.vpn_server_id == server.id,
            )
        )
        if assignment is None:
            assignment = UserServerAssignment(
                user_id=user.id,
                vpn_server_id=server.id,
                assigned_by_admin_id=None,
                state=LifecycleState.ACTIVE.value,
                assigned_at=now,
            )
            session.add(assignment)
        elif assignment.state != LifecycleState.ACTIVE.value:
            assignment.state = LifecycleState.ACTIVE.value
            assignment.assigned_at = now
            assignment.revoked_at = None
        await session.flush()

        session.add(
            AuditLog(
                actor_kind="bootstrap",
                actor_id=None,
                target_kind="assignment",
                target_id=assignment.id,
                event_code="assignment_changed",
                outcome="succeeded",
                request_id=None,
                correlation_id=None,
                reason_code="assigned",
            )
        )
        return GrantAccessResult(
            status=GrantAccessStatus.GRANTED, user_id=user.id, profile_codes=granted
        )
