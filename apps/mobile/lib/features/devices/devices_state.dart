import '../../core/servers/server_repository.dart';
import '../../core/tunnel/tunnel_traffic.dart';
import '../../core/xray/local_proxy.dart';

enum DevicesLoadStatus { loading, failed, loaded }

/// The protocol choice that lets the app pick: tried in order, the next one
/// when a protocol does not carry traffic. Stored like a profile code, so a
/// choice is still one string everywhere it is kept.
const String automaticProfileCode = 'auto';

enum DelayOutcome {
  /// Being measured now.
  testing,

  /// A real request went through the profile, in [ProtocolDelay.milliseconds].
  measured,

  /// The request did not come back: from this network, right now, the
  /// profile does not carry traffic.
  failed,
}

/// One profile's real delay, v2ray-style: a request actually sent through it.
class ProtocolDelay {
  const ProtocolDelay.testing()
    : outcome = DelayOutcome.testing,
      milliseconds = null,
      megabits = null;
  const ProtocolDelay.measured(int this.milliseconds, {this.megabits})
    : outcome = DelayOutcome.measured;
  const ProtocolDelay.failed()
    : outcome = DelayOutcome.failed,
      milliseconds = null,
      megabits = null;

  final DelayOutcome outcome;
  final int? milliseconds;

  /// Megabits a second from the download after the delay test, where this
  /// platform measures one; negative when nothing arrived.
  final double? megabits;
}

/// State for the devices/connect screen. A single class (not a sealed
/// hierarchy) because most fields are meaningful across every load status
/// once a first load has completed -- e.g. an in-flight connect action's
/// error should stay visible even if a background reload starts.
class DevicesState {
  const DevicesState({
    required this.loadStatus,
    this.servers = const <AvailableServer>[],
    this.loadErrorMessage,
    this.selectedServerCode,
    this.selectedProfileCode,
    this.peer,
    this.xrayClient,
    this.connectedServerCode,
    this.activeProtocolCode,
    this.activeProfileCode,
    this.tunnelEstablished = false,
    this.tunnelEstablishedAt,
    this.trafficBaseline,
    this.sanctionsOnly = false,
    this.fromSavedCredential = false,
    this.protocolDelays = const <String, ProtocolDelay>{},
    this.protocolDelaysServer,
    this.pinging = false,
    this.localProxy,
    this.isSubmitting = false,
    this.actionErrorMessage,
  });

  static const DevicesState initial = DevicesState(
    loadStatus: DevicesLoadStatus.loading,
  );

  final DevicesLoadStatus loadStatus;
  final List<AvailableServer> servers;
  final String? loadErrorMessage;
  final String? selectedServerCode;
  final String? selectedProfileCode;

  /// The active WireGuard peer configuration, once a WireGuard connect
  /// request has succeeded. Mutually exclusive with [xrayClient] -- exactly
  /// one is set once connected, chosen by [activeProtocolCode].
  /// Provisioning this peer registers the device with the VPN server --
  /// [tunnelEstablished] is the separate signal for whether a live local
  /// tunnel is actually up, since the two can disagree (e.g. the server
  /// accepted the peer but the local platform failed to bring the tunnel
  /// up, or this platform has no tunnel support at all yet).
  final WireGuardPeerResult? peer;

  /// The active Xray client configuration, once an Xray connect request has
  /// succeeded. Mutually exclusive with [peer] -- see its doc comment.
  final XrayClientResult? xrayClient;

  /// Whether the live tunnel carries only sanctioned services.
  ///
  /// Recorded when the tunnel comes up, from the settings it was built with,
  /// rather than read from the settings now: flipping the switch while
  /// connected changes the next connection, not this one, and the Connect
  /// screen must describe the one that is running.
  final bool sanctionsOnly;

  /// This connection was raised from a credential already on the phone,
  /// because the server could not be reached to issue a fresh one. Recorded
  /// so the app can say so rather than implying the server confirmed it.
  final bool fromSavedCredential;

  /// The last per-protocol test, by profile code. Read through [delaysFor]:
  /// every server names its protocols the same way, and one server's results
  /// were shown on another's chips -- and ranked its protocols for Automatic.
  final Map<String, ProtocolDelay> protocolDelays;

  /// The server [protocolDelays] were measured on.
  final String? protocolDelaysServer;

  /// What to call [profileCode] on screen: the name the server gives it
  /// ("VLESS (WebSocket+TLS)"), or for a link of the device's own the name
  /// its link gives it. Codes such as `vless-xhttp-tls-adblock` were shown
  /// before, which mean nothing to most people (2026-10-29). The code is the
  /// fallback for a profile no listed server describes.
  String profileLabel(String profileCode) {
    for (final AvailableServer server in servers) {
      for (final AvailableProfile profile in server.profiles) {
        if (profile.code == profileCode && profile.displayName.isNotEmpty) {
          return profile.displayName;
        }
      }
    }
    return profileCode;
  }

  /// The last test's results for [serverCode]; none if it was not tested.
  Map<String, ProtocolDelay> delaysFor(String? serverCode) =>
      serverCode != null && serverCode == protocolDelaysServer
      ? protocolDelays
      : const <String, ProtocolDelay>{};

  /// A per-protocol test is running.
  final bool pinging;

  /// The proxy the connection runs as in local proxy mode, and null for a
  /// VPN. Recorded with the connection, like [sanctionsOnly]: switching the
  /// mode while connected changes the next connection, and the screen has
  /// to describe the one that is running.
  final LocalProxy? localProxy;

  /// Which server [peer]/[xrayClient] belongs to -- needed to send the
  /// right `server_code` on revoke, since the picker's current selection
  /// may have moved on since connecting.
  final String? connectedServerCode;

  /// Which protocol (`"wireguard"`, `"vless"`, `"hysteria2"`, ...) the
  /// current connection used -- lets `connect`/`disconnect` know which
  /// repository call and tunnel controller pair to use, since
  /// [peer]/[xrayClient] alone can't disambiguate a disconnect issued
  /// before either is populated.
  final String? activeProtocolCode;

  /// Which profile (e.g. `"vless-xhttp-tls"`, `"hysteria2"`) the current
  /// Xray connection used -- needed to send the right
  /// `protocol_profile_code` on revoke, since a device can hold a live
  /// client per profile simultaneously and the picker's current selection
  /// may have moved on since connecting. `null` for a WireGuard connection.
  final String? activeProfileCode;

  /// Whether the real local tunnel (Android's VpnService via WireGuard or
  /// Xray, or Windows' `wireguard.exe`-managed tunnel service) is actually
  /// up. False on platforms/protocols with no tunnel support yet, or if it
  /// failed to start even though the server-side peer/client was
  /// provisioned successfully.
  final bool tunnelEstablished;

  /// When the live tunnel came up, for transports whose engine cannot
  /// report their own session length.
  ///
  /// Null when unknown, which is a real answer rather than a missing one:
  /// a tunnel still running from before this process started began at a
  /// moment nothing here observed, and a clock started at zero would be a
  /// plausible number that is simply wrong.
  final DateTime? tunnelEstablishedAt;

  /// The engine's counters when this session began, when known. Belongs to
  /// the session clock above: setting that clock without this clears it.
  final TunnelTraffic? trafficBaseline;

  final bool isSubmitting;
  final String? actionErrorMessage;

  bool get isConnected => peer != null || xrayClient != null;

  AvailableServer? get selectedServer {
    final String? code = selectedServerCode;
    if (code == null) {
      return null;
    }
    for (final AvailableServer server in servers) {
      if (server.code == code) {
        return server;
      }
    }
    return null;
  }

  DevicesState copyWith({
    DevicesLoadStatus? loadStatus,
    List<AvailableServer>? servers,
    String? Function()? loadErrorMessage,
    String? Function()? selectedServerCode,
    String? Function()? selectedProfileCode,
    WireGuardPeerResult? Function()? peer,
    XrayClientResult? Function()? xrayClient,
    String? Function()? connectedServerCode,
    String? Function()? activeProtocolCode,
    String? Function()? activeProfileCode,
    bool? tunnelEstablished,
    DateTime? Function()? tunnelEstablishedAt,
    TunnelTraffic? Function()? trafficBaseline,
    bool? sanctionsOnly,
    bool? fromSavedCredential,
    Map<String, ProtocolDelay>? protocolDelays,
    String? Function()? protocolDelaysServer,
    bool? pinging,
    LocalProxy? Function()? localProxy,
    bool? isSubmitting,
    String? Function()? actionErrorMessage,
  }) {
    return DevicesState(
      loadStatus: loadStatus ?? this.loadStatus,
      servers: servers ?? this.servers,
      loadErrorMessage: loadErrorMessage != null
          ? loadErrorMessage()
          : this.loadErrorMessage,
      selectedServerCode: selectedServerCode != null
          ? selectedServerCode()
          : this.selectedServerCode,
      selectedProfileCode: selectedProfileCode != null
          ? selectedProfileCode()
          : this.selectedProfileCode,
      peer: peer != null ? peer() : this.peer,
      xrayClient: xrayClient != null ? xrayClient() : this.xrayClient,
      connectedServerCode: connectedServerCode != null
          ? connectedServerCode()
          : this.connectedServerCode,
      activeProtocolCode: activeProtocolCode != null
          ? activeProtocolCode()
          : this.activeProtocolCode,
      activeProfileCode: activeProfileCode != null
          ? activeProfileCode()
          : this.activeProfileCode,
      tunnelEstablished: tunnelEstablished ?? this.tunnelEstablished,
      tunnelEstablishedAt: tunnelEstablishedAt == null
          ? this.tunnelEstablishedAt
          : tunnelEstablishedAt(),
      // A new session clock is a new session: its baseline goes with the old
      // one unless given alongside.
      trafficBaseline: trafficBaseline != null
          ? trafficBaseline()
          : tunnelEstablishedAt != null
          ? null
          : this.trafficBaseline,
      sanctionsOnly: sanctionsOnly ?? this.sanctionsOnly,
      fromSavedCredential: fromSavedCredential ?? this.fromSavedCredential,
      protocolDelays: protocolDelays ?? this.protocolDelays,
      protocolDelaysServer: protocolDelaysServer != null
          ? protocolDelaysServer()
          : this.protocolDelaysServer,
      pinging: pinging ?? this.pinging,
      localProxy: localProxy != null ? localProxy() : this.localProxy,
      isSubmitting: isSubmitting ?? this.isSubmitting,
      actionErrorMessage: actionErrorMessage != null
          ? actionErrorMessage()
          : this.actionErrorMessage,
    );
  }
}
