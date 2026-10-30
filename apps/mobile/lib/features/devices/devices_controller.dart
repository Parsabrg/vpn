import 'dart:async';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/account/account_repository.dart';
import '../../core/diagnostics/server_reach.dart';
import '../../core/free/free_mode.dart';
import '../../core/network/api_client.dart';
import '../../core/network/api_exception.dart';
import '../../core/network/api_route_sync.dart';
import '../../core/network/error_copy.dart';
import '../../core/network/network_guard.dart';
import '../../core/routing/tunnel_routes.dart';
import '../../core/servers/server_repository.dart';
import '../../core/settings/advanced_settings_controller.dart';
import '../../core/settings/locale_controller.dart';
import '../../core/settings/protection_controller.dart';
import '../../core/split_tunnel/split_tunnel_controller.dart';
import '../../core/storage/advanced_settings_store.dart';
import '../../core/storage/connection_record_store.dart';
import '../../core/storage/protocol_history_store.dart';
import '../../core/storage/selection_store.dart';
import '../../core/storage/storage_providers.dart';
import '../../core/storage/wireguard_key_store.dart';
import '../../core/storage/xray_credential_store.dart';
import '../../core/tunnel/tunnel_health.dart';
import '../../core/tunnel/tunnel_traffic.dart';
import '../../core/wireguard/tunnel_controller.dart';
import '../../core/wireguard/wireguard_config.dart';
import '../../core/wireguard/wireguard_keys.dart';
import '../../core/xray/cdn_dial_store.dart';
import '../../core/xray/ech_source.dart';
import '../../core/xray/local_proxy.dart';
import '../../core/xray/xray_config.dart';
import '../../core/xray/xray_tunnel_controller.dart';
import '../../l10n/app_localizations.dart';
import 'devices_state.dart';
import 'profile_order.dart';
import 'profile_quality.dart';

/// This app's server-side WireGuard protocol code -- every other protocol
/// code (`"vless"`, `"hysteria2"`, ...) is Xray-engine per the server's own
/// `code_engine_pair` CHECK constraint, so anything that isn't this one
/// routes through the Xray path rather than needing a per-protocol branch
/// here for every new transport.
const String wireguardProtocolCode = 'wireguard';

/// How many settle steps a new WireGuard tunnel gets to complete a
/// handshake: 75 at the default 200 ms is 15 seconds, the first attempt and
/// two retries.
const int _handshakeWaitSteps = 75;

class DevicesController extends Notifier<DevicesState> {
  late ServerRepository _repository;
  late WireGuardKeyStore _keyStore;
  late TunnelController _tunnel;
  late XrayTunnelController _xrayTunnel;
  late SelectionStore _selections;
  late ConnectionRecordStore _records;
  static const WireGuardKeyGenerator _keyGenerator = WireGuardKeyGenerator();

  /// Checks, while a tunnel is reported up, that Android still lists one.
  Timer? _tunnelWatch;
  Timer? _accessWatch;
  Timer? _trafficWatch;
  Timer? _trafficSoon;
  bool _checkingTraffic = false;
  bool _checkingAccess = false;

  // Connect attempts, numbered so Cancel can tell the one in flight to stand
  // down. [_liveAttempt] is zero when none is in flight or it was cancelled;
  // [_attemptRun] completes when the latest attempt, undo included, is done.
  int _attemptCounter = 0;
  int _liveAttempt = 0;
  Future<void>? _attemptRun;

  // The record write in progress, so a baseline noted a moment after a
  // connect lands in the record rather than before it.
  Future<void>? _recordWriting;

  /// The device the running connection was made for, kept so a tunnel that
  /// ends on its own can be revoked without reaching back into storage.
  String? _connectedDeviceId;
  int _tunnelMissingReadings = 0;

  /// Consecutive watch readings in which the interface was up but the engine
  /// behind it was dead. See _checkEngine.
  int _engineDeadReadings = 0;

  /// When a dead engine last triggered an automatic reconnect. One attempt
  /// per [_engineRecoveryInterval], so a server that is truly gone produces
  /// "Off" and a message, not a loop.
  DateTime? _lastEngineRecovery;

  /// Consecutive requests that did not come back through an Xray or
  /// Hysteria2 tunnel. See _checkTraffic.
  int _trafficFailedReadings = 0;
  static const Duration _engineRecoveryInterval = Duration(minutes: 2);

  /// The local proxy of the tunnel this app last started, which the traffic
  /// check asks through. Null for one picked back up after a restart.
  LocalProxy? _tunnelProxy;

  /// Stops calling [_checkTrafficOnResume] when the app is opened again.
  void Function()? _stopResumeWatch;

  @override
  DevicesState build() {
    _repository = ref.watch(serverRepositoryProvider);
    _keyStore = ref.watch(wireGuardKeyStoreProvider);
    _tunnel = ref.watch(tunnelControllerProvider);
    _xrayTunnel = ref.watch(xrayTunnelControllerProvider);
    _selections = ref.watch(selectionStoreProvider);
    _records = ref.watch(connectionRecordStoreProvider);
    ref.onDispose(_stopWatchingTunnel);
    // Listened to, not watched: a rebuild would drop the live connection.
    ref.listen<AdvancedSettings>(advancedSettingsControllerProvider, (
      AdvancedSettings? previous,
      AdvancedSettings next,
    ) {
      if (previous != null && routingChanged(previous, next)) {
        // Queued, so flipping a switch twice ends on the last setting.
        _routingReconnect = (_routingReconnect ?? Future<void>.value()).then(
          (_) => _reconnectForRouting(),
        );
      }
    });
    return DevicesState.initial;
  }

  Future<void>? _routingReconnect;

  /// Reconnects the running connection so a routing setting changed in
  /// Settings applies now rather than from the next connection, which
  /// looked like the switch doing nothing.
  ///
  /// Only when the selection still names the connected server: having
  /// picked another one since, reconnecting would quietly switch servers.
  Future<void> _reconnectForRouting() async {
    final String? deviceId = _connectedDeviceId ?? _storedDeviceId();
    if (!ref.mounted ||
        deviceId == null ||
        !state.isConnected ||
        state.isSubmitting ||
        state.connectedServerCode != state.selectedServerCode) {
      return;
    }
    await disconnect(deviceId);
    if (ref.mounted) {
      await connect(deviceId);
    }
  }

  /// Read at connect time rather than captured in [build].
  ///
  /// Changing which apps bypass the tunnel has to take effect on the next
  /// connection, and watching this here would rebuild the controller -- and
  /// so drop the live connection -- every time somebody ticked a box in the
  /// picker while connected.
  List<String> get _excludedPackages =>
      excludedPackagesFor(ref.read(splitTunnelControllerProvider));

  /// Read at connect time for the same reason as the exclusions above: the
  /// route list is fixed when the VpnService is established, so watching it
  /// would drop a live tunnel the moment somebody flipped the switch.
  List<String> get _routes => tunnelRoutes(
    bypassLocalNetwork: ref
        .read(protectionControllerProvider)
        .bypassLocalNetwork,
  );

  /// Whether this run has already considered connecting on its own.
  ///
  /// "On launch" means once. Retrying the server list after an error, or
  /// coming back to the tab, is not a launch, and must not start a tunnel
  /// somebody may have just turned off.
  bool _launchConnectConsidered = false;

  /// Connects to the last used server, if the setting asks for it.
  ///
  /// Only with a server and profile restored from an earlier run, so a
  /// first launch never connects to something nobody chose. Only while VPN
  /// consent is still held: another VPN app takes it away, and a system
  /// dialog appearing the moment the app opens would be a surprise. And
  /// never over a VPN that is already up -- this app's tunnel can outlive
  /// the app, and starting it again would drop a working connection.
  ///
  /// Called after [load], never from it: the restored selection is what it
  /// reads, and it waits on the device rather than on the server list.
  Future<void> connectOnLaunchIfWanted(String? deviceId) async {
    if (_launchConnectConsidered) {
      return;
    }
    _launchConnectConsidered = true;
    if (deviceId == null ||
        !ref.read(protectionControllerProvider).connectOnLaunch ||
        state.loadStatus != DevicesLoadStatus.loaded ||
        state.selectedServerCode == null ||
        state.selectedProfileCode == null ||
        state.tunnelEstablished ||
        state.isSubmitting) {
      return;
    }
    // A protocol picked by hand that failed last time is not tried again
    // unasked: a dead server held every launch at Connecting for over a
    // minute (2026-10-17). Automatic still runs; it moves on by itself.
    final String serverCode = state.selectedServerCode!;
    final String profileCode = state.selectedProfileCode!;
    if (profileCode != automaticProfileCode) {
      ProtocolHistory? last;
      try {
        last = ref
            .read(protocolHistoryStoreProvider)
            .forServer(serverCode)[profileCode];
      } catch (_) {
        // No history is the same as none.
      }
      final DateTime? failedAt = last?.lastFailureAt;
      final DateTime? workedAt = last?.lastSuccessAt;
      if (failedAt != null &&
          (workedAt == null || failedAt.isAfter(workedAt))) {
        return;
      }
    }
    // Whose VPN first: a VPN of any kind is left alone on launch, and asking
    // about consent only makes sense once there is none. A local proxy needs
    // neither: it is not a VPN, and runs beside one.
    final bool proxyMode =
        ref.read(advancedSettingsControllerProvider).connectionMode ==
        ConnectionMode.localProxy;
    if (!proxyMode &&
        (await _tunnel.activeVpn() != VpnOwner.none ||
            !await _tunnel.hasPermission())) {
      return;
    }
    await connect(deviceId);
  }

  /// The tunnel notification's Disconnect button.
  ///
  /// The button opens the app instead of stopping the service itself, so
  /// this goes the same way as Disconnect on screen: the tunnel comes down
  /// and the server revokes the client, rather than leaving a credential
  /// live on a server nobody is connected to.
  ///
  /// Opening the app to disconnect must not also connect it on launch. And
  /// a tunnel this run knows nothing about -- still up from before the app
  /// was last closed -- is stopped all the same; there is just no client
  /// on record to revoke.
  Future<void> disconnectFromNotification(String? deviceId) async {
    _launchConnectConsidered = true;
    // A connect still in flight finishes first. Its result landing after
    // the disconnect would put back what the tap took away.
    final Duration step = ref.read(tunnelSettleStepProvider);
    for (int waited = 0; waited < 100 && state.isSubmitting; waited++) {
      await Future<void>.delayed(step);
    }
    // A tunnel still up from an earlier run is picked back up first, so it
    // can be revoked like any other rather than only stopped.
    await _adoptRunningTunnel();
    if (deviceId != null && state.connectedServerCode != null) {
      await disconnect(deviceId);
      return;
    }
    await _stopLeftoverTunnel();
  }

  /// Takes this app's tunnel down without asking the server anything.
  ///
  /// For when the server cannot be reached -- which a tunnel that is up but
  /// carrying nothing causes by itself, because the app's own requests go
  /// into it. There is nothing to revoke from here; the server prunes a
  /// client it stops hearing from.
  Future<void> stopTunnelWithoutServer() async {
    _launchConnectConsidered = true;
    await _stopLeftoverTunnel();
  }

  /// Shows the tunnel that is actually up, when this run did not start it.
  ///
  /// Reopening the app while connected used to show "Off" over a working
  /// VPN, and offer to connect again. Now the connection recorded when the
  /// tunnel came up is restored -- only while Android reports the VPN that
  /// is up as this app's own.
  ///
  /// The session clock stays unknown rather than starting at zero: nothing
  /// in this run saw the tunnel come up.
  Future<void> _adoptRunningTunnel() async {
    if (state.isConnected || state.isSubmitting) {
      return;
    }
    try {
      // Cheap and local first. Storage is read only when something of this
      // app's could be running: a VPN of its own, or local proxy mode. Reading
      // it on every load put a secure-storage call on the path of every
      // screen that loads servers, and in widget tests that call never
      // returns -- the suite hung for ten minutes on the servers screen.
      final bool proxyMode =
          ref.read(advancedSettingsControllerProvider).connectionMode ==
          ConnectionMode.localProxy;
      final bool ownVpn = await _tunnel.activeVpn() == VpnOwner.own;
      if (!ownVpn && !proxyMode) {
        return;
      }
      final ConnectionRecord? record = await _records.read();
      final int? proxyPort = record?.localProxyPort;
      final bool up = proxyPort != null
          ? await ref.read(loopbackPortProbeProvider)(proxyPort)
          : ownVpn;
      if (!up) {
        return;
      }
      final LocalProxy? proxy = proxyPort == null
          ? null
          : await ref
                .read(localProxyAccountStoreProvider)
                .readOrCreate(proxyPort);
      if (record == null ||
          !ref.mounted ||
          state.isConnected ||
          state.isSubmitting) {
        return;
      }
      final bool serverListed = state.servers.any(
        (AvailableServer server) => server.code == record.serverCode,
      );
      final AdoptedSession session = adoptedSession(
        record,
        restoredAt: await _lastRestore(),
        now: DateTime.now(),
      );
      if (!ref.mounted || state.isConnected || state.isSubmitting) {
        return;
      }
      state = state.copyWith(
        peer: () => record.peer,
        xrayClient: () => record.xrayClient,
        connectedServerCode: () => record.serverCode,
        activeProtocolCode: () => record.protocolCode,
        activeProfileCode: () => record.profileCode,
        tunnelEstablished: true,
        tunnelEstablishedAt: () => session.since,
        trafficBaseline: () => session.baseline,
        sanctionsOnly: record.sanctionsOnly,
        localProxy: () => proxy,
        // The screen names the server from the selection, so it has to be
        // the one the tunnel runs through, not whatever was picked since.
        selectedServerCode: serverListed ? () => record.serverCode : null,
        // Automatic stays Automatic: the protocol in use is shown from
        // activeProfileCode, and the next connect should choose again.
        selectedProfileCode: serverListed
            ? () => _selections.readProfileCode() == automaticProfileCode
                  ? automaticProfileCode
                  : record.profileCode
            : null,
      );
      // The same engine runs on, so its proxy is the one recorded.
      _tunnelProxy = record.tunnelProxy;
      if (record.xrayClient != null) {
        await _xrayTunnel.attach();
      }
      _watchTunnel();
    } catch (_) {
      // Unable to tell is the same as nothing to adopt.
    }
  }

  Future<DateTime?> _lastRestore() async {
    try {
      return await ref.read(tunnelRestoreStoreProvider).lastRestoredAt();
    } catch (_) {
      // Unknown is taken as never: the recorded session stands.
      return null;
    }
  }

  /// Keeps the counters' reading at the start of this session, the first
  /// time the screen sees one, so a reopened app's figures continue from it.
  ///
  /// Only for a session whose start was seen, and only once: a later reading
  /// would put the start in the wrong place. Written to the record and not to
  /// state -- the traffic figures are built from state, and changing it on
  /// their first reading would start them over.
  Future<void> rememberTrafficBaseline(TunnelTraffic reading) async {
    if (!ref.mounted ||
        !state.tunnelEstablished ||
        state.tunnelEstablishedAt == null) {
      return;
    }
    final TunnelTraffic baseline = TunnelTraffic(
      rxBytes: reading.rxBytes,
      txBytes: reading.txBytes,
    );
    try {
      await _recordWriting;
      final ConnectionRecord? record = await _records.read();
      if (record == null || record.trafficBaseline != null) {
        return;
      }
      await _records.write(record.withTrafficBaseline(baseline));
    } catch (_) {
      // Without it a reopened app counts from the reopen, as it always did.
    }
  }

  /// Records the connection a tunnel just came up on. Never fails a connect:
  /// without the record, a reopened app is only less informed.
  Future<void> _recordConnection() async {
    final String? serverCode = state.connectedServerCode;
    final String? profileCode = state.activeProfileCode;
    final String? protocolCode = state.activeProtocolCode;
    if (serverCode == null || profileCode == null || protocolCode == null) {
      return;
    }
    try {
      final Future<void> writing = _records.write(
        ConnectionRecord(
          serverCode: serverCode,
          profileCode: profileCode,
          protocolCode: protocolCode,
          sanctionsOnly: state.sanctionsOnly,
          peer: state.peer,
          xrayClient: state.xrayClient,
          localProxyPort: state.localProxy?.port,
          tunnelProxy: state.xrayClient == null ? null : _tunnelProxy,
          establishedAt: state.tunnelEstablishedAt,
        ),
      );
      _recordWriting = writing;
      await writing;
    } catch (_) {}
  }

  Future<void> _forgetConnection() async {
    try {
      await _records.clear();
    } catch (_) {}
  }

  Future<void> load() async {
    state = state.copyWith(loadStatus: DevicesLoadStatus.loading);
    try {
      final List<AvailableServer> servers = await runGuarded(
        ref,
        _repository.listAvailableServers,
      );
      state = state.copyWith(
        loadStatus: DevicesLoadStatus.loaded,
        servers: servers,
      );
      _restoreSelection(servers);
      // With no server there is usually one relay, and nothing to weigh:
      // the first is chosen rather than leaving "Choose" on the screen. The
      // same for an account with a single server: a new user saw "Choose"
      // twice and a disabled Connect, with nothing to choose between.
      if (state.selectedServerCode == null &&
          servers.isNotEmpty &&
          (ref.read(freeModeProvider) || servers.length == 1)) {
        selectServer(servers.first.code);
        // Chosen for the person, not by them: this launch does not connect
        // to it on its own. The next one finds it remembered and may.
        _launchConnectConsidered = true;
      }
      // The server list arrived, so this address works right now -- which is
      // the only moment the list of other addresses can be refreshed. Never
      // awaited, and never able to fail this screen: it is housekeeping for a
      // future block, and a list that stays as it was is no worse than it was
      // a minute ago.
      try {
        unawaited(ref.read(apiRouteSyncProvider).refresh());
      } catch (_) {
        // Including storage not being available at all, as in a headless
        // test: loading the screen does not depend on any of this.
      }
      await _adoptRunningTunnel();
    } catch (error) {
      state = state.copyWith(
        loadStatus: DevicesLoadStatus.failed,
        loadErrorMessage: () =>
            userFacingErrorMessage(error, ref.read(appTextProvider)),
      );
    }
  }

  /// Puts back what was chosen last time, if it is still choosable.
  ///
  /// A remembered choice is a hint, not an instruction. A server can be
  /// withdrawn from an account and a profile disabled between one launch and
  /// the next, so each half is checked against what actually came back before
  /// it is restored -- silently selecting something the account can no longer
  /// reach would fail at connect time with nothing explaining why.
  ///
  /// Only fills what is empty. A choice made during this run always wins over
  /// one restored from disk.
  void _restoreSelection(List<AvailableServer> servers) {
    if (state.selectedServerCode != null) {
      return;
    }
    final String? rememberedServer = _selections.readServerCode();
    if (rememberedServer == null) {
      return;
    }
    AvailableServer? server = servers
        .where(
          (AvailableServer candidate) => candidate.code == rememberedServer,
        )
        .firstOrNull;
    String? rememberedProfile = _selections.readProfileCode();
    if (server == null && isOwnLinkCode(rememberedServer)) {
      // Saved before links were grouped, the link was its own "server", and
      // its group now holds it under the same code. Saved by 0.1.24, the
      // group's code came from its name, now from its address: the link
      // chosen in it finds it again.
      final String? link = isOwnLinkCode(rememberedProfile)
          ? rememberedProfile
          : rememberedServer;
      server = servers
          .where(
            (AvailableServer candidate) =>
                candidate.profiles.any((AvailableProfile p) => p.code == link),
          )
          .firstOrNull;
      rememberedProfile = link;
    }
    final AvailableServer? found = server;
    if (found == null) {
      return;
    }
    final String? profile = rememberedProfile;
    final bool profileStillOffered = found.profiles.any(
      (AvailableProfile offered) => offered.code == profile,
    );

    state = state.copyWith(
      selectedServerCode: () => found.code,
      // Automatic unless a protocol the server still offers was chosen.
      selectedProfileCode: () =>
          profileStillOffered ? profile : automaticProfileCode,
    );
  }

  void selectServer(String serverCode) {
    state = state.copyWith(
      selectedServerCode: () => serverCode,
      // Changing servers invalidates any profile chosen for the old one;
      // the app chooses until the person does.
      selectedProfileCode: () => automaticProfileCode,
      // A message about the last attempt is about a choice no longer made.
      actionErrorMessage: () => null,
    );
    unawaited(_selections.writeServerCode(serverCode));
    unawaited(_selections.writeProfileCode(automaticProfileCode));
  }

  void selectProfile(String profileCode) {
    // Clearing the last attempt's message too: the one telling you to pick
    // another protocol should not outlive your picking one.
    state = state.copyWith(
      selectedProfileCode: () => profileCode,
      actionErrorMessage: () => null,
    );
    unawaited(_selections.writeProfileCode(profileCode));
  }

  Future<void> connect(String deviceId) async {
    _connectedDeviceId = deviceId;
    final String? serverCode = state.selectedServerCode;
    final String? profileCode = state.selectedProfileCode;
    if (serverCode == null || profileCode == null) {
      return;
    }
    if (state.selectedServer?.maintenance ?? false) {
      // Said before anything is registered or started: the server would
      // refuse, and this says why.
      state = state.copyWith(
        actionErrorMessage: () =>
            ref.read(appTextProvider).errorServerMaintenance,
      );
      return;
    }

    final int attempt = ++_attemptCounter;
    _liveAttempt = attempt;
    final Future<void>? previous = _attemptRun;
    final Completer<void> run = Completer<void>();
    _attemptRun = run.future;
    try {
      if (previous != null) {
        // A cancelled attempt can still be undoing what it started. Its
        // teardown landing after this one's tunnel came up would take the
        // new connection down with it, so this one waits its turn.
        state = state.copyWith(
          isSubmitting: true,
          actionErrorMessage: () => null,
        );
        await previous;
        if (!ref.mounted || _cancelled(attempt)) {
          return;
        }
        state = state.copyWith(isSubmitting: false);
      }

      if (profileCode == automaticProfileCode) {
        await _connectAutomatically(
          attempt: attempt,
          deviceId: deviceId,
          serverCode: serverCode,
        );
      } else {
        await _connectProfile(
          attempt: attempt,
          deviceId: deviceId,
          serverCode: serverCode,
          profileCode: profileCode,
        );
      }
    } finally {
      if (_liveAttempt == attempt) {
        _liveAttempt = 0;
      }
      run.complete();
      if (identical(_attemptRun, run.future)) {
        _attemptRun = null;
      }
    }
  }

  Future<void> _connectProfile({
    required int attempt,
    required String deviceId,
    required String serverCode,
    required String profileCode,
  }) async {
    if (_protocolCodeFor(profileCode) != wireguardProtocolCode) {
      await _connectXray(
        attempt: attempt,
        deviceId: deviceId,
        serverCode: serverCode,
        protocolProfileCode: profileCode,
      );
    } else {
      await _connectWireGuard(
        attempt: attempt,
        deviceId: deviceId,
        serverCode: serverCode,
        protocolProfileCode: profileCode,
      );
    }
    if (!ref.mounted || _cancelled(attempt)) {
      return;
    }
    if (state.tunnelEstablished) {
      await _recordProtocol(serverCode, profileCode, ProtocolOutcome.success);
    } else if (_aboutTheProtocol(state.actionErrorMessage)) {
      await _recordProtocol(serverCode, profileCode, ProtocolOutcome.failure);
    }
  }

  /// Whether a failed connect says something about the protocol, rather than
  /// the account, the server as a whole, or this device being offline --
  /// none of which another protocol would change, so none count against it.
  bool _aboutTheProtocol(String? error) {
    final AppText text = ref.read(appTextProvider);
    return error == text.errorTunnelNoTraffic ||
        error == text.errorWireguardNoHandshake ||
        error == text.errorServerCertificate;
  }

  Future<void> _recordProtocol(
    String serverCode,
    String profileCode,
    ProtocolOutcome outcome,
  ) async {
    try {
      await ref
          .read(protocolHistoryStoreProvider)
          .record(serverCode, profileCode, outcome);
    } catch (_) {
      // A record that could not be kept only costs ordering later.
    }
  }

  static String _inboundOf(String profileCode) =>
      profileCode.endsWith('-adblock')
      ? profileCode.substring(0, profileCode.length - '-adblock'.length)
      : profileCode;

  /// At most this many protocols per Automatic connect. A protocol that
  /// carries nothing is found out in about 20 s; a server offering twelve
  /// would otherwise keep somebody at Connecting for four minutes.
  static const int _automaticTries = 4;

  /// Automatic: one protocol after another until one carries traffic.
  ///
  /// First the one that last worked on this server, then the list's own
  /// order -- the last test's fastest first, no answer last, gRPC after the
  /// rest. Each try is a whole connect, whose own checks say whether traffic
  /// got through and undo it if not, so a failed try leaves nothing behind.
  /// Stops at once for what no other protocol would change: an allowance
  /// used up, or the server asking the device to slow down.
  Future<void> _connectAutomatically({
    required int attempt,
    required String deviceId,
    required String serverCode,
  }) async {
    final AvailableServer? server = state.servers
        .where((AvailableServer s) => s.code == serverCode)
        .firstOrNull;
    if (server == null || server.profiles.isEmpty) {
      return;
    }
    // Hand-picked only (see AvailableProfile.manualOnly), unless a server
    // offers nothing else.
    final List<AvailableProfile> candidates =
        server.profiles.any((AvailableProfile p) => !p.manualOnly)
        ? server.profiles
              .where((AvailableProfile p) => !p.manualOnly)
              .toList(growable: false)
        : server.profiles;
    String? lastWorked;
    try {
      final ConnectionRecord? record = await _records.read();
      if (record?.serverCode == serverCode) {
        lastWorked = record!.profileCode;
      }
    } catch (_) {
      // No history is the same as none.
    }
    Map<String, ProtocolHistory> history = <String, ProtocolHistory>{};
    try {
      history = ref.read(protocolHistoryStoreProvider).forServer(serverCode);
    } catch (_) {
      // No history is the same as none.
    }
    // Best quality first (roadmap section 9): this device's own record of
    // each protocol here, and the last test. The last one that worked leads
    // the input, so it wins a tie -- and with no record yet, the order is
    // the one Automatic always used.
    final Set<String> inbounds = <String>{};
    final List<AvailableProfile> order =
        rankByQuality(
              <AvailableProfile>[
                ...candidates.where(
                  (AvailableProfile p) => p.code == lastWorked,
                ),
                ...orderedProfiles(
                  candidates,
                  state.delaysFor(server.code),
                  pinging: false,
                ).where((AvailableProfile p) => p.code != lastWorked),
              ],
              history,
              state.delaysFor(server.code),
              DateTime.now().toUtc(),
            )
            // A protocol and its ad-block twin are one inbound on the server: if
            // one carries nothing so does the other. Trying both spent half of
            // Automatic's tries on Cloudflare routes that were stalled, and the
            // one protocol that worked was never reached (Windows, 2026-10-29).
            .where((AvailableProfile p) => inbounds.add(_inboundOf(p.code)))
            .take(_automaticTries)
            .toList();

    final AppText text = ref.read(appTextProvider);
    for (final AvailableProfile profile in order) {
      if (!ref.mounted || _cancelled(attempt)) {
        return;
      }
      state = state.copyWith(actionErrorMessage: () => null);
      await _connectProfile(
        attempt: attempt,
        deviceId: deviceId,
        serverCode: serverCode,
        profileCode: profile.code,
      );
      if (!ref.mounted || _cancelled(attempt) || state.tunnelEstablished) {
        return;
      }
      final String? error = state.actionErrorMessage;
      // A refused VPN permission is the person's answer, not the network's:
      // the next protocol would ask again, and the closing "none of the
      // protocols got through" would hide why (found on a first install,
      // 2026-10-17).
      if (error == text.errorQuotaExhausted ||
          error == text.errorRateLimited ||
          error == text.errorOffline ||
          error == text.vpnPermissionNotGranted ||
          error ==
              text.errorProxyPortInUse(
                '${ref.read(advancedSettingsControllerProvider).localProxyPort}',
              )) {
        return;
      }
    }
    if (ref.mounted && !_cancelled(attempt)) {
      state = state.copyWith(
        isSubmitting: false,
        actionErrorMessage: () => text.errorNoProtocolWorked,
      );
    }
  }

  /// Whether Cancel can do anything: a connect is in flight and has not been
  /// cancelled already. The Connecting screen also covers a disconnect, which
  /// is not something to cancel.
  bool get canCancelConnect => _liveAttempt != 0;

  /// Cancel on the Connecting screen.
  ///
  /// The screen goes back to Off at once. The attempt cannot be stopped
  /// mid-step -- a request already sent will be answered, a tunnel already
  /// starting will start -- so it stands down at its next step and undoes
  /// what it got as far as. Waiting for that instead would keep somebody who
  /// pressed Cancel looking at Connecting for as long as a slow network takes
  /// to answer, which is exactly when they press it.
  void cancelConnect() {
    if (_liveAttempt == 0) {
      return;
    }
    _liveAttempt = 0;
    state = state.copyWith(
      isSubmitting: false,
      peer: () => null,
      xrayClient: () => null,
      connectedServerCode: () => null,
      activeProtocolCode: () => null,
      activeProfileCode: () => null,
      tunnelEstablished: false,
      tunnelEstablishedAt: () => null,
      sanctionsOnly: false,
      localProxy: () => null,
      actionErrorMessage: () => null,
    );
  }

  bool _cancelled(int attempt) => attempt != _liveAttempt;

  /// Undoes what a cancelled connect got as far as: the tunnel, if it had
  /// started, and the credential, if the server had issued one -- so nothing
  /// is left live on a server for a connection nobody wanted.
  ///
  /// Never touches the screen. Cancel already put it back to Off, and a
  /// connect started since may own it by now.
  Future<void> _undoCancelledConnect({
    required String deviceId,
    required String serverCode,
    required String profileCode,
    required bool xray,
    required bool tunnelStarted,
  }) async {
    if (tunnelStarted) {
      try {
        if (xray) {
          await _xrayTunnel.disconnect();
        } else {
          await _tunnel.disconnect();
        }
        // The same settle as a disconnect: the revoke below would otherwise
        // race Android switching the default route back.
        await Future<void>.delayed(const Duration(milliseconds: 600));
      } catch (_) {
        // Revoke regardless.
      }
    }
    if (!ref.mounted) {
      return;
    }
    try {
      if (xray) {
        await _revokeXrayClient(
          deviceId: deviceId,
          serverCode: serverCode,
          protocolProfileCode: profileCode,
        );
      } else {
        await _repository.revokePeer(
          deviceId: deviceId,
          serverCode: serverCode,
        );
      }
    } catch (_) {
      // The server prunes a credential nobody connects with.
    }
  }

  Future<void> _connectWireGuard({
    required int attempt,
    required String deviceId,
    required String serverCode,
    required String protocolProfileCode,
  }) async {
    // WireGuard is a VPN protocol with no proxy to run as. Connecting it as
    // a VPN anyway would quietly do the opposite of the switch.
    if (ref.read(advancedSettingsControllerProvider).connectionMode ==
        ConnectionMode.localProxy) {
      state = state.copyWith(
        actionErrorMessage: () =>
            ref.read(appTextProvider).errorWireguardNotProxy,
      );
      return;
    }
    state = state.copyWith(isSubmitting: true, actionErrorMessage: () => null);
    try {
      final WireGuardKeyPair keyPair = await _currentOrNewKeyPair();
      final WireGuardPeerResult result = await runGuarded(
        ref,
        () => _repository.requestPeer(
          deviceId: deviceId,
          serverCode: serverCode,
          protocolProfileCode: protocolProfileCode,
          publicKey: keyPair.publicKeyBase64,
        ),
      );
      if (!ref.mounted) {
        return;
      }
      if (_cancelled(attempt)) {
        await _undoCancelledConnect(
          deviceId: deviceId,
          serverCode: serverCode,
          profileCode: protocolProfileCode,
          xray: false,
          tunnelStarted: false,
        );
        return;
      }
      // The server-side peer is provisioned regardless of what happens
      // next -- record it even if bringing up the local tunnel fails, so
      // the user isn't shown "not connected" when the server actually did
      // accept them.
      state = state.copyWith(
        peer: () => result,
        connectedServerCode: () => serverCode,
        activeProtocolCode: () => wireguardProtocolCode,
        activeProfileCode: () => protocolProfileCode,
      );

      bool tunnelUp = false;
      String? tunnelError;
      try {
        await _stopLeftoverTunnel();
        final bool granted = await _tunnel.requestPermission();
        if (!granted) {
          tunnelError = ref.read(appTextProvider).vpnPermissionNotGranted;
        } else {
          await _tunnel.connect(
            renderWireGuardConfig(
              privateKeyBase64: keyPair.privateKeyBase64,
              peer: result,
              bypassLocalNetwork: ref
                  .read(protectionControllerProvider)
                  .bypassLocalNetwork,
            ),
            excludedPackages: _excludedPackages,
            killSwitch: ref
                .read(protectionControllerProvider)
                .blockWhenVpnDrops,
          );
          tunnelUp = true;
        }
      } catch (error) {
        tunnelError = userFacingErrorMessage(error, ref.read(appTextProvider));
      }

      if (!ref.mounted) {
        return;
      }
      // A handshake alone is not traffic: on a network that lets the
      // server's packets in and drops the phone's, the phone answers the
      // server's handshakes and the tunnel still carries nothing ("Protected"
      // for minutes on the phone, 2026-10-17). This app's own requests go
      // through a WireGuard tunnel, so a plain one asks the question.
      if (!_cancelled(attempt) &&
          tunnelUp &&
          !(await _serverAnswered(attempt) &&
              await _tunnelCarriesTraffic(attempt, viaProxy: false)) &&
          !_cancelled(attempt)) {
        // The interface is up and the server never answered, so nothing
        // this device sends goes anywhere. Saying "Protected" over that is
        // the one thing this screen must not do: it looks connected, and
        // every app on the phone quietly stops working. Undo the connection,
        // server side included, and say why.
        if (!ref.mounted) {
          return;
        }
        state = state.copyWith(isSubmitting: false, tunnelEstablished: true);
        await disconnect(deviceId);
        if (ref.mounted) {
          state = state.copyWith(
            actionErrorMessage: () =>
                ref.read(appTextProvider).errorWireguardNoHandshake,
          );
        }
        return;
      }
      if (!ref.mounted) {
        return;
      }
      if (_cancelled(attempt)) {
        await _undoCancelledConnect(
          deviceId: deviceId,
          serverCode: serverCode,
          profileCode: protocolProfileCode,
          xray: false,
          tunnelStarted: tunnelUp,
        );
        return;
      }

      state = state.copyWith(
        isSubmitting: false,
        tunnelEstablished: tunnelUp,
        // Recorded only when this process saw the tunnel come up, so a
        // session it did not start reports no elapsed time rather than a
        // wrong one.
        tunnelEstablishedAt: () => tunnelUp ? DateTime.now() : null,
        actionErrorMessage: () => tunnelError,
      );
      if (tunnelUp) {
        _watchTunnel();
        await _recordConnection();
      }
    } catch (error) {
      if (!ref.mounted || _cancelled(attempt)) {
        return;
      }
      state = state.copyWith(
        isSubmitting: false,
        actionErrorMessage: () =>
            userFacingErrorMessage(error, ref.read(appTextProvider)),
      );
    }
  }

  /// Asks the server for this protocol's credential and saves it. True when
  /// it differs from [saved] in anything the connection is made with.
  Future<bool> _serverChangedCredential({
    required String deviceId,
    required String serverCode,
    required String profileCode,
    required XrayClientResult saved,
  }) async {
    try {
      final XrayClientResult fresh = await runGuarded(
        ref,
        () => _repository.requestXrayClient(
          deviceId: deviceId,
          serverCode: serverCode,
          protocolProfileCode: profileCode,
        ),
      );
      await _remember(
        ref.read(xrayCredentialStoreProvider),
        serverCode: serverCode,
        profileCode: profileCode,
        credential: fresh,
      );
      return fresh.uuid != saved.uuid ||
          fresh.serverAddress != saved.serverAddress ||
          fresh.port != saved.port ||
          fresh.sni != saved.sni ||
          fresh.transport != saved.transport ||
          fresh.path != saved.path ||
          fresh.password != saved.password;
    } catch (_) {
      return false;
    }
  }

  /// After a connect from the saved credential: the request every connect
  /// used to make first. What the server says still counts -- an allowance
  /// used up, access expired, the server in maintenance, the client revoked
  /// -- and takes the connection down with its reason. Not reaching the
  /// server changes nothing: the tunnel already proved it carries traffic.
  Future<void> _confirmWithServer({
    required String deviceId,
    required String serverCode,
    required String profileCode,
  }) async {
    try {
      final XrayClientResult fresh = await runGuarded(
        ref,
        () => _repository.requestXrayClient(
          deviceId: deviceId,
          serverCode: serverCode,
          protocolProfileCode: profileCode,
        ),
      );
      await _remember(
        ref.read(xrayCredentialStoreProvider),
        serverCode: serverCode,
        profileCode: profileCode,
        credential: fresh,
      );
    } on NebulaConnectivityException {
      // Kept: see above. Said on screen, as for any connection the server
      // did not confirm, and replaced once it answers (refreshAfterOffline).
      if (ref.mounted && state.activeProfileCode == profileCode) {
        state = state.copyWith(fromSavedCredential: true);
      }
    } on NebulaApiException catch (error) {
      // Only a definite no takes a working tunnel down. A sign-in that could
      // not be renewed (401), a busy server (429, 5xx) or a conflict says
      // nothing about this connection: treated as a refusal, a token refresh
      // failing on a flaky network dropped the phone's tunnel over and over
      // (2026-10-19).
      final bool refused =
          error.isQuotaExhausted ||
          error.isServerMaintenance ||
          error.isAccountExpired ||
          error.statusCode == 400 ||
          error.statusCode == 404;
      if (!refused ||
          !ref.mounted ||
          !state.tunnelEstablished ||
          state.activeProfileCode != profileCode) {
        return;
      }
      await disconnect(deviceId);
      if (ref.mounted) {
        state = state.copyWith(
          actionErrorMessage: () =>
              userFacingErrorMessage(error, ref.read(appTextProvider)),
        );
      }
    } catch (_) {
      // Anything else is not the server's answer; keep the connection.
    }
  }

  /// Revokes a client on the server and forgets any saved copy of it.
  ///
  /// The two go together or the saved copy lies: a later offline connect
  /// from it raises a tunnel on a credential the server no longer accepts --
  /// carrying nothing while the app says it is connected. Measured on a phone
  /// when Disconnect still revoked.
  Future<void> _revokeXrayClient({
    required String deviceId,
    required String serverCode,
    required String protocolProfileCode,
  }) async {
    await _repository.revokeXrayClient(
      deviceId: deviceId,
      serverCode: serverCode,
      protocolProfileCode: protocolProfileCode,
    );
    try {
      await ref
          .read(xrayCredentialStoreProvider)
          .forget(serverCode: serverCode, profileCode: protocolProfileCode);
    } catch (_) {
      // A copy that could not be deleted is refused later anyway: the server
      // no longer knows the credential, and this is not worth failing a
      // disconnect over.
    }
  }

  /// Keeps the credential for a connect the server cannot answer later.
  ///
  /// Storage failing is never a reason to refuse a connection that is
  /// otherwise fine: the keystore can be unavailable (a device mid-upgrade,
  /// a headless test), and the cost is only that the next offline connect
  /// has nothing to fall back on.
  Future<void> _remember(
    XrayCredentialStore store, {
    required String serverCode,
    required String profileCode,
    required XrayClientResult credential,
  }) async {
    try {
      await store.write(
        serverCode: serverCode,
        profileCode: profileCode,
        credential: credential,
      );
    } catch (_) {
      // Deliberately swallowed; see above.
    }
  }

  /// The counterpart: an unreadable store means no saved credential, which
  /// the caller already handles.
  Future<XrayClientResult?> _recalled(
    XrayCredentialStore store, {
    required String serverCode,
    required String profileCode,
  }) async {
    try {
      return await store.read(serverCode: serverCode, profileCode: profileCode);
    } catch (_) {
      return null;
    }
  }

  /// The Cloudflare dial that carried traffic last, if the store can say.
  CdnDial? _lastCdnDial() {
    try {
      return ref.read(lastCdnDialProvider).read();
    } on Object {
      return null;
    }
  }

  Future<void> _connectXray({
    required int attempt,
    required String deviceId,
    required String serverCode,
    required String protocolProfileCode,
    bool trySaved = true,
    List<CdnDial>? cdnDials,
  }) async {
    state = state.copyWith(isSubmitting: true, actionErrorMessage: () => null);
    try {
      final XrayCredentialStore credentials = ref.read(
        xrayCredentialStoreProvider,
      );
      XrayClientResult result;
      bool fromSavedCredential = false;
      // The credential this phone already holds, first: the server hands the
      // same one back on every request, so asking before connecting only
      // adds a round trip to an API the network may be slowing -- 30 s on a
      // filtered day, against v2rayNG's instant start from its saved config
      // (2026-10-18). The server is asked afterwards, in the background; a
      // saved credential that carries nothing is replaced by asking first.
      final XrayClientResult? saved = trySaved
          ? await _recalled(
              credentials,
              serverCode: serverCode,
              profileCode: protocolProfileCode,
            )
          : null;
      final bool usedSaved = saved != null;
      if (saved != null) {
        result = saved;
      } else {
        try {
          result = await runGuarded(
            ref,
            () => _repository.requestXrayClient(
              deviceId: deviceId,
              serverCode: serverCode,
              protocolProfileCode: protocolProfileCode,
            ),
          );
          await _remember(
            credentials,
            serverCode: serverCode,
            profileCode: protocolProfileCode,
            credential: result,
          );
        } on NebulaConnectivityException {
          // Nobody answered. The credential already on this phone is a UUID on
          // an inbound and stays valid until an admin revokes it, so the tunnel
          // can still come up -- which is the whole point when the API's
          // address is blocked and the tunnel is the only way back to it.
          //
          // ponytail: not re-checked with the server, because there is no
          // server to ask. A credential revoked in the meantime would raise a
          // tunnel that carries nothing, so the app says plainly that this
          // connection was made from saved credentials. If that becomes a real
          // failure rather than a theoretical one, probe through the local
          // proxy before reporting connected.
          final XrayClientResult? saved = await _recalled(
            credentials,
            serverCode: serverCode,
            profileCode: protocolProfileCode,
          );
          if (saved == null) {
            rethrow;
          }
          result = saved;
          fromSavedCredential = true;
        }
      }
      if (!ref.mounted) {
        return;
      }
      if (_cancelled(attempt)) {
        await _undoCancelledConnect(
          deviceId: deviceId,
          serverCode: serverCode,
          profileCode: protocolProfileCode,
          xray: true,
          tunnelStarted: false,
        );
        return;
      }
      // Same honesty invariant as the WireGuard path -- the server-side
      // client is provisioned regardless of what happens next.
      state = state.copyWith(
        xrayClient: () => result,
        fromSavedCredential: fromSavedCredential,
        connectedServerCode: () => serverCode,
        activeProtocolCode: () =>
            _protocolCodeFor(protocolProfileCode) ?? protocolProfileCode,
        activeProfileCode: () => protocolProfileCode,
      );

      // Read at connect time, not watched: the config is built once per
      // connection, and watching would rebuild the controller and drop a live
      // tunnel whenever a setting changed. Held here so the state can record
      // the routing this connection was actually built with.
      final AdvancedSettings settings = ref.read(
        advancedSettingsControllerProvider,
      );
      // Through Cloudflare, the dials still to try for this credential: the
      // one that carried traffic last first (see CdnDial).
      final List<CdnDial> dials = isCloudflareRoute(result)
          ? cdnDials ??
                cdnDialOrder(
                  lastWorked: _lastCdnDial(),
                  hasIpv6: await ref.read(deviceHasIpv6Provider)(),
                )
          : const <CdnDial>[CdnDial.asGiven];
      final CdnDial dial = dials.first;
      bool tunnelUp = false;
      String? tunnelError;
      final bool proxyMode =
          settings.connectionMode == ConnectionMode.localProxy;
      LocalProxy? runningProxy;
      try {
        await _stopLeftoverTunnel();
        // A local proxy needs no VPN consent, but it does need its port:
        // another app already listening there would leave the engine
        // unable to start, reported as nothing more than a failed connect.
        final bool portTaken =
            proxyMode &&
            await ref.read(loopbackPortProbeProvider)(settings.localProxyPort);
        final bool granted = proxyMode || await _xrayTunnel.requestPermission();
        if (portTaken) {
          tunnelError = ref
              .read(appTextProvider)
              .errorProxyPortInUse('${settings.localProxyPort}');
        } else if (!granted) {
          tunnelError = ref.read(appTextProvider).vpnPermissionNotGranted;
        } else {
          final LocalProxy localProxy = proxyMode
              ? await ref
                    .read(localProxyAccountStoreProvider)
                    .readOrCreate(settings.localProxyPort)
              : await ref.read(localProxyFactoryProvider)();
          _tunnelProxy = proxyMode ? null : localProxy;
          await ref.read(echServerRefreshProvider)(echConfigListFor(result));
          await _xrayTunnel.connect(
            renderXrayClientConfigJson(
              result,
              settings: settings,
              localProxy: localProxy,
              apiHosts: ref.read(apiHostsProvider),
              cdnDial: dial,
            ),
            excludedPackages: _excludedPackages,
            killSwitch: ref
                .read(protectionControllerProvider)
                .blockWhenVpnDrops,
            routes: _routes,
            // What people chose, not an internal code: it is the title in
            // the shade and the name in Android's own VPN line.
            sessionName: state.selectedServer?.displayName ?? serverCode,
            notificationShowsSpeed: ref
                .read(protectionControllerProvider)
                .notificationSpeed,
            disconnectLabel: ref.read(appTextProvider).ctaDisconnect,
            proxyOnly: proxyMode,
          );
          tunnelUp = true;
          runningProxy = proxyMode ? localProxy : null;
        }
      } catch (error) {
        tunnelError = userFacingErrorMessage(error, ref.read(appTextProvider));
      }

      if (!ref.mounted) {
        return;
      }
      // A local proxy carries only what is sent to it, so there is nothing
      // to check from here; a tunnel carries this app's requests too.
      if (!_cancelled(attempt) &&
          tunnelUp &&
          runningProxy == null &&
          !await _tunnelCarriesTraffic(attempt) &&
          !_cancelled(attempt)) {
        // Xray's tunnel is up the moment the engine starts, whether or not
        // the server is there. Seen on Windows with saved credentials for a
        // server that was gone: "Protected" for a minute and a half while
        // every lookup failed. Undo it, as WireGuard's missing handshake is.
        if (!ref.mounted) {
          return;
        }
        state = state.copyWith(isSubmitting: false, tunnelEstablished: true);
        await disconnect(deviceId);
        // The same credential through Cloudflare, dialled the next way: each
        // of Iran's firewalls lets a different shape through.
        if (dials.length > 1 && !_cancelled(attempt)) {
          await _connectXray(
            attempt: attempt,
            deviceId: deviceId,
            serverCode: serverCode,
            protocolProfileCode: protocolProfileCode,
            cdnDials: dials.sublist(1),
          );
          return;
        }
        // A saved credential the server has since changed carries nothing:
        // ask the server, as every connect used to, and try once more only
        // if it hands out something different. The same one again would
        // just double the wait on a network that blocks this protocol.
        if (usedSaved &&
            !_cancelled(attempt) &&
            await _serverChangedCredential(
              deviceId: deviceId,
              serverCode: serverCode,
              profileCode: protocolProfileCode,
              saved: result,
            ) &&
            !_cancelled(attempt)) {
          await _connectXray(
            attempt: attempt,
            deviceId: deviceId,
            serverCode: serverCode,
            protocolProfileCode: protocolProfileCode,
          );
          return;
        }
        // Nothing gets through a tunnel on a device that is not online at
        // all either -- in offline mode, from a saved credential, nothing
        // else would have noticed. That is not a blocked protocol, and the
        // next protocol would not help.
        // Off screen on Android this app's own requests may be held back
        // (see trafficCheckMeaningfulProvider): a connect finished there
        // called an online phone offline (2026-10-29). Its checks are not
        // asked, and the failure is put as what is known -- nothing got
        // through the tunnel.
        final bool inFront = ref.read(trafficCheckMeaningfulProvider)();
        final bool online = !inFront || await ref.read(deviceOnlineProvider)();
        // Online: then which step to the server failed, if any, says more
        // than "may be blocking it" (roadmap 79).
        // The tunnel's address came from the API's route in use. Asked again
        // over the next one (a CDN, a web-host front), the API hands out a
        // tunnel through that one instead -- the way past an address that is
        // throttled rather than blocked.
        if (online &&
            ref.read(moveApiRouteProvider)() &&
            !_cancelled(attempt)) {
          await _connectXray(
            attempt: attempt,
            deviceId: deviceId,
            serverCode: serverCode,
            protocolProfileCode: protocolProfileCode,
          );
          return;
        }
        final ServerReach reach = online && inFront
            ? await ref.read(serverReachProvider)(result)
            : ServerReach.reachable;
        if (ref.mounted) {
          final AppText text = ref.read(appTextProvider);
          state = state.copyWith(
            actionErrorMessage: () => !online
                ? text.errorOffline
                : switch (reach) {
                    ServerReach.nameNotFound => text.errorServerNameNotFound,
                    ServerReach.unreachable => text.errorServerUnreachable,
                    ServerReach.certificateRejected =>
                      text.errorServerCertificate,
                    ServerReach.reachable => text.errorTunnelNoTraffic,
                  },
          );
        }
        return;
      }
      if (!ref.mounted) {
        return;
      }
      if (_cancelled(attempt)) {
        await _undoCancelledConnect(
          deviceId: deviceId,
          serverCode: serverCode,
          profileCode: protocolProfileCode,
          xray: true,
          tunnelStarted: tunnelUp,
        );
        return;
      }
      if (tunnelUp && isCloudflareRoute(result)) {
        try {
          await ref.read(lastCdnDialProvider).write(dial);
        } on Object {
          // A hint for next time; the connection does not depend on it.
        }
      }
      state = state.copyWith(
        isSubmitting: false,
        tunnelEstablished: tunnelUp,
        // Recorded only when this process saw the tunnel come up, so a
        // session it did not start reports no elapsed time rather than a
        // wrong one.
        tunnelEstablishedAt: () => tunnelUp ? DateTime.now() : null,
        sanctionsOnly: tunnelUp && routesSanctionsOnly(result, settings),
        localProxy: () => runningProxy,
        actionErrorMessage: () => tunnelError,
      );
      if (tunnelUp) {
        _watchTunnel();
        await _recordConnection();
        // What the Cloudflare address scan tests. Learned here, on every
        // CDN connection: learned only by opening that screen while
        // connected, a connect-then-disconnect left it saying "connect
        // once" (reported 2026-10-18).
        if (cdnTransports.contains(result.transport)) {
          unawaited(
            ref
                .read(advancedSettingsControllerProvider.notifier)
                .rememberCdnHost(result.serverAddress),
          );
        }
        if (usedSaved) {
          unawaited(
            _confirmWithServer(
              deviceId: deviceId,
              serverCode: serverCode,
              profileCode: protocolProfileCode,
            ),
          );
        }
      }
    } catch (error) {
      if (!ref.mounted || _cancelled(attempt)) {
        return;
      }
      state = state.copyWith(
        isSubmitting: false,
        actionErrorMessage: () =>
            userFacingErrorMessage(error, ref.read(appTextProvider)),
      );
    }
  }

  /// Takes down a tunnel this app left running, before starting another.
  ///
  /// A tunnel outlives the screen that started it, so reopening the app
  /// can find one up that this run knows nothing about. The Xray plugin
  /// cannot start over it: it stops the old service, starts the core,
  /// reports CONNECTED -- and then the old service's shutdown lands on the
  /// new core. On the phone that read "Protected" with no tunnel at all.
  ///
  /// So stop first, and wait until Android no longer lists a VPN: the same
  /// sequence as disconnecting and connecting again by hand, which works.
  /// Only when this app holds VPN consent, because consent is held by one
  /// app at a time -- a VPN that is up while this app holds it is this
  /// app's, and anyone else's is left for Android's own consent dialog.
  ///
  /// Never fails a connect. The wait is bounded: a WireGuard tunnel from an
  /// earlier run belongs to a backend object that is gone and cannot be
  /// stopped from here, and the watch started after connecting reports
  /// honestly on whatever happens next.
  Future<void> _stopLeftoverTunnel() async {
    try {
      // Unknown is stopped too: the stops below only ever reach this app's
      // own engines, so they cannot take anyone else's VPN down.
      final VpnOwner? vpn = await _tunnel.activeVpn();
      final int? proxyPort = (await _records.read())?.localProxyPort;
      final Future<bool> Function(int) portOpen = ref.read(
        loopbackPortProbeProvider,
      );
      final bool proxyUp = proxyPort != null && await portOpen(proxyPort);
      if (!proxyUp && (vpn == VpnOwner.none || vpn == VpnOwner.other)) {
        return;
      }
      _stopWatchingTunnel();
      for (final Future<void> Function() stop in <Future<void> Function()>[
        _xrayTunnel.disconnect,
        _tunnel.disconnect,
      ]) {
        try {
          await stop();
        } catch (_) {
          // The other engine may be the one that was running.
        }
      }
      final Duration step = ref.read(tunnelSettleStepProvider);
      for (int waited = 0; waited < 25; waited++) {
        final bool stillProxy = proxyPort != null && await portOpen(proxyPort);
        if (!stillProxy && await _tunnel.activeVpn() != VpnOwner.own) {
          break;
        }
        await Future<void>.delayed(step);
      }
      await _forgetConnection();
      // The interface closes a moment before the old service is destroyed,
      // and its teardown stops whatever core is running in the process --
      // including a new one started in that moment.
      await Future<void>.delayed(step * 4);
    } catch (_) {
      // A question the platform could not answer is not a reason to refuse
      // to connect.
    }
  }

  /// Keeps "Protected" honest for as long as it is on screen.
  ///
  /// The plugin reports CONNECTED once the core starts, and nothing after
  /// that: a tunnel torn down a moment later left the screen claiming
  /// protection over traffic that was going out directly. So Android is
  /// asked on an interval whether a VPN is still up.
  ///
  /// Two missing readings in a row, not one: the VPN network is registered
  /// a beat after the service starts, and a single early reading would call
  /// a healthy tunnel dead. A platform that cannot tell never trips it.
  void _watchTunnel() {
    _stopWatchingTunnel();
    _tunnelWatch = Timer.periodic(
      ref.read(tunnelWatchIntervalProvider),
      (_) => _checkTunnel(),
    );
    _accessWatch = Timer.periodic(
      ref.read(accessCheckIntervalProvider),
      (_) => unawaited(_checkAccess()),
    );
    _trafficWatch = Timer.periodic(
      ref.read(trafficCheckIntervalProvider),
      (_) => unawaited(_checkTraffic()),
    );
    // A route that is throttled rather than blocked lets the connect's own
    // request through and stalls seconds later (Cloudflare from Iran,
    // 2026-10-29): asked again soon, not a minute on.
    _checkTrafficSoon();
    _stopResumeWatch = ref.read(appResumedProvider)(() {
      unawaited(_checkTunnel());
      unawaited(_checkTrafficOnResume());
      unawaited(_checkAccess());
    });
  }

  void _stopWatchingTunnel() {
    _tunnelWatch?.cancel();
    _tunnelWatch = null;
    _tunnelMissingReadings = 0;
    _engineDeadReadings = 0;
    _accessWatch?.cancel();
    _accessWatch = null;
    _trafficWatch?.cancel();
    _trafficSoon?.cancel();
    _trafficSoon = null;
    _trafficWatch = null;
    _trafficFailedReadings = 0;
    _stopResumeWatch?.call();
    _stopResumeWatch = null;
  }

  /// Stops a tunnel whose access has ended, and says why.
  ///
  /// The server takes credentials away within about a minute of access
  /// ending -- an allowance spent, the account or a grant expired, the
  /// device revoked, the account disabled. The tunnel on this device then
  /// carries nothing, and nothing on the device says so: the VPN is still
  /// up, so the screen went on showing "Protected". Asking the server is the
  /// only way to find out, and this app's own requests bypass the tunnel, so
  /// the question still gets through.
  ///
  /// Quiet when the answer does not arrive -- offline, or the API busy --
  /// because a tunnel is not stopped on an answer nobody gave.
  Future<void> _checkAccess() async {
    // With no server there is no access to end, and nobody to ask: a build
    // that also carries a server's address would be told "not signed in"
    // and take the tunnel down for it.
    // Nor on one of this device's own links, which an account's allowance,
    // expiry or devices have nothing to do with.
    // Only with the app in front of the person (on Android), like the
    // traffic check, and once more when it comes back: two API requests
    // every 30 seconds kept the phone's radio awake all night -- 35 minutes
    // of it for under 100 MB in 2.5 hours, measured. The server refuses a
    // revoked device or an ended account by itself; this is only how the
    // screen finds out sooner.
    if (_checkingAccess ||
        !state.tunnelEstablished ||
        !ref.read(trafficCheckMeaningfulProvider)() ||
        ref.read(freeModeProvider) ||
        isOwnLinkCode(state.connectedServerCode)) {
      return;
    }
    _checkingAccess = true;
    try {
      final AccountRepository accounts = ref.read(accountRepositoryProvider);
      final AccountSummary account;
      final List<AccountDevice> devices;
      try {
        account = await accounts.fetchAccount();
        devices = await accounts.listDevices();
      } on NebulaApiException catch (error) {
        if (error.statusCode == 401 || error.statusCode == 403) {
          // The session is over, not merely unreachable: the device was
          // revoked or the account disabled. Signing out follows; the tunnel
          // goes now, without asking a server that will not answer.
          await _endTunnel(reason: null, revokeOnServer: false);
        }
        return;
      } on Object {
        return;
      }
      if (!ref.mounted || !state.tunnelEstablished) {
        return;
      }
      final AppText text = ref.read(appTextProvider);
      final String? reason;
      if (account.isMetered && (account.remainingBytes ?? 0) <= 0) {
        reason = text.errorQuotaExhausted;
      } else if (account.hasExpiredAt(DateTime.now())) {
        reason = text.accessExpired;
      } else if (!_holdsAccess(devices)) {
        reason = text.errorAccessEnded;
      } else {
        reason = null;
      }
      if (reason != null) {
        await _endTunnel(reason: reason, revokeOnServer: true);
      }
    } finally {
      _checkingAccess = false;
    }
  }

  /// Whether this device still holds a live credential on the server it is
  /// connected to -- which is what an expired grant, an admin, or the server
  /// pruning it takes away. A device no longer listed has been revoked.
  bool _holdsAccess(List<AccountDevice> devices) {
    final String? server = state.connectedServerCode;
    // One of this device's own links: no account is behind it.
    if (isOwnLinkCode(server)) {
      return true;
    }
    for (final AccountDevice device in devices) {
      if (device.isCurrent) {
        return server == null || device.serverCodes.contains(server);
      }
    }
    return false;
  }

  /// Ends the connection and shows [reason], if there is one.
  ///
  /// [revokeOnServer] where the session still works: the server has taken
  /// the credential already or is about to, and saying so again is harmless.
  /// Without a session there is nobody to tell, so the tunnel is only
  /// stopped.
  Future<void> _endTunnel({
    required String? reason,
    required bool revokeOnServer,
  }) async {
    _stopWatchingTunnel();
    final String? deviceId = _connectedDeviceId ?? _storedDeviceId();
    if (revokeOnServer && deviceId != null) {
      await disconnect(deviceId);
    } else {
      await stopTunnelWithoutServer();
      await _forgetConnection();
    }
    if (!ref.mounted) {
      return;
    }
    // A revoke inside disconnect may well be refused; off all the same.
    state = state.copyWith(
      isSubmitting: false,
      peer: () => null,
      xrayClient: () => null,
      connectedServerCode: () => null,
      activeProtocolCode: () => null,
      activeProfileCode: () => null,
      tunnelEstablished: false,
      tunnelEstablishedAt: () => null,
      sanctionsOnly: false,
      localProxy: () => null,
      actionErrorMessage: () => reason,
    );
  }

  /// Disconnects properly before a sign-out, while the session can still
  /// tell the server. Leaving the tunnel up would keep a credential live for
  /// an account nobody is signed in to on this device.
  Future<void> disconnectBeforeSignOut() async {
    if (!state.isConnected && !state.tunnelEstablished) {
      return;
    }
    await _endTunnel(reason: null, revokeOnServer: true);
  }

  /// Stops the tunnel after the session ended without this device asking --
  /// revoked or expired. Nothing can be revoked any more; the server does
  /// its own removal.
  Future<void> endAfterSessionLost() async {
    if (!state.isConnected && !state.tunnelEstablished) {
      return;
    }
    await _endTunnel(reason: null, revokeOnServer: false);
  }

  /// Whether the engine behind a present interface still carries traffic.
  ///
  /// The interface check above cannot see this. A WireGuard session whose
  /// server stopped answering, or an xray/hysteria process that exited, leaves
  /// the VPN interface registered and every packet going nowhere -- and the
  /// screen said Protected over it. Two dead readings in a row take the
  /// tunnel down to Off with the reason, then try once to bring it back.
  Future<void> _checkEngine() async {
    final EngineHealth health;
    try {
      if (state.peer != null) {
        health = wireguardHealth(
          await _tunnel.latestHandshake(),
          DateTime.now(),
        );
      } else if (state.xrayClient != null) {
        health = engineProcessHealth(await _xrayTunnel.engineRunning());
      } else {
        return;
      }
    } catch (_) {
      return;
    }
    if (!ref.mounted || _tunnelWatch == null) {
      return;
    }
    if (health != EngineHealth.dead) {
      _engineDeadReadings = 0;
      return;
    }
    _engineDeadReadings++;
    if (_engineDeadReadings < 2 ||
        state.isSubmitting ||
        !state.tunnelEstablished) {
      return;
    }
    await _endDeadTunnel();
  }

  /// Whether an Xray or Hysteria2 tunnel still carries a request.
  ///
  /// The process check in [_checkEngine] cannot see this: the engine runs on
  /// when its server is blocked partway through a session, and nothing it
  /// logs says so. WireGuard has its handshake for this; here one small
  /// request is sent each interval, the one a connect is checked with. Three
  /// in a row unanswered -- about as long as WireGuard is given -- and the
  /// tunnel is taken down and tried again once, where the connect says which
  /// it was: offline, the server gone, or the protocol blocked.
  Future<void> _checkTraffic({bool data = false}) async {
    // A local proxy carries only what is sent to it.
    if (_checkingTraffic ||
        state.xrayClient == null ||
        state.localProxy != null ||
        state.isSubmitting ||
        !state.tunnelEstablished ||
        !ref.read(trafficCheckMeaningfulProvider)()) {
      return;
    }
    _checkingTraffic = true;
    try {
      final bool carries = await _tunnelAnswers(data: data);
      if (!ref.mounted || _trafficWatch == null) {
        return;
      }
      if (carries) {
        _trafficFailedReadings = 0;
        return;
      }
      _trafficFailedReadings++;
      if (_trafficFailedReadings < 3 ||
          state.isSubmitting ||
          !state.tunnelEstablished) {
        // Confirmed or cleared within seconds: three one-a-minute readings
        // kept a stalled tunnel reading "Protected" for three minutes.
        if (_trafficFailedReadings < 3) {
          _checkTrafficSoon();
        }
        return;
      }
      await _endDeadTunnel();
    } finally {
      _checkingTraffic = false;
    }
  }

  void _checkTrafficSoon() {
    _trafficSoon?.cancel();
    _trafficSoon = Timer(
      ref.read(trafficRecheckDelayProvider),
      () => unawaited(_checkTraffic(data: true)),
    );
  }

  /// One reading of the traffic watch: a request through the tunnel, and a
  /// DNS question over its UDP side -- the way every app's DNS goes, and
  /// which the request alone never touches (the proxy looks its name up
  /// itself, over TCP).
  Future<bool> _tunnelAnswers({bool data = false}) async {
    // The soon readings also move real data: a throttled route answers one
    // small request and stalls a transfer, and read "Protected" for minutes
    // with 170 KB moved (Windows, 2026-10-30). Not every minute: that would
    // be 180 MB a day on a phone's data plan.
    if (data &&
        (!await ref.read(tunnelMovesDataProvider)(_tunnelProxy) ||
            !ref.mounted)) {
      return false;
    }
    final LocalProxy? proxy = _tunnelProxy;
    if (!await ref.read(tunnelCarriesTrafficProvider)(proxy) || !ref.mounted) {
      return false;
    }
    final InternetAddress? resolver = _tunnelResolver();
    return proxy == null ||
        resolver == null ||
        await ref.read(tunnelResolvesProvider)(proxy, resolver);
  }

  /// Where this app's own measurements -- the diagnostics -- must go to
  /// cross the tunnel, or null where they already do.
  ///
  /// On Android this app is outside its own Xray/Hysteria2 VPN, so a request
  /// from it measures the bare line: the speed and packet-loss tests said
  /// "through the VPN" over the ISP's figures, and the leak test reported
  /// the real address and the ISP's forged DNS as leaks. They go through the
  /// tunnel's local proxy instead -- or, in local proxy mode, through that,
  /// which is what a proxied app gets. WireGuard and the desktop carry the
  /// app's own traffic, so nothing is needed there.
  ({LocalProxy proxy, InternetAddress? resolver})? get measurementRoute {
    if (!state.tunnelEstablished) {
      return null;
    }
    final LocalProxy? proxy =
        state.localProxy ??
        (defaultTargetPlatform == TargetPlatform.android &&
                state.xrayClient != null
            ? _tunnelProxy
            : null);
    return proxy == null ? null : (proxy: proxy, resolver: _tunnelResolver());
  }

  /// The first IPv4 resolver the tunnel hands Android, or null.
  InternetAddress? _tunnelResolver() {
    final XrayClientResult? client = state.xrayClient;
    if (client == null) {
      return null;
    }
    final Object? servers = dnsModuleFor(
      client,
      ref.read(advancedSettingsControllerProvider),
    )['servers'];
    for (final Object? server
        in servers is List ? servers : const <Object?>[]) {
      final InternetAddress? address = server is String
          ? InternetAddress.tryParse(server)
          : null;
      if (address?.type == InternetAddressType.IPv4) {
        return address;
      }
    }
    return null;
  }

  /// Checks the tunnel the moment the app is opened again.
  ///
  /// Off screen on Android, [_checkTraffic] asks nothing (see
  /// trafficCheckMeaningfulProvider), so a tunnel that died meanwhile still
  /// read "Connected" when the app was opened -- and went on reading it
  /// through three more one-a-minute checks. Here it is asked at once, three
  /// times a couple of seconds apart, and taken down and tried again if none
  /// of them is answered.
  Future<void> _checkTrafficOnResume() async {
    bool unchanged() =>
        ref.mounted &&
        _trafficWatch != null &&
        !state.isSubmitting &&
        state.tunnelEstablished;
    if (_checkingTraffic ||
        state.xrayClient == null ||
        state.localProxy != null ||
        !unchanged()) {
      return;
    }
    _checkingTraffic = true;
    try {
      for (int tried = 0; tried < 3; tried++) {
        if (tried > 0) {
          await Future<void>.delayed(const Duration(seconds: 2));
        }
        if (!unchanged()) {
          return;
        }
        if (await _tunnelAnswers()) {
          _trafficFailedReadings = 0;
          return;
        }
      }
      if (unchanged()) {
        await _endDeadTunnel();
      }
    } finally {
      _checkingTraffic = false;
    }
  }

  /// Takes down a tunnel that carries nothing, and tries once to bring it
  /// back.
  Future<void> _endDeadTunnel() async {
    final String? deviceId = _connectedDeviceId ?? _storedDeviceId();
    final String? deadServer = state.connectedServerCode;
    final String? deadProfile = state.activeProfileCode;
    if (deadServer != null && deadProfile != null) {
      await _recordProtocol(deadServer, deadProfile, ProtocolOutcome.drop);
    }
    final DateTime now = DateTime.now();
    final DateTime? last = _lastEngineRecovery;
    final bool retry =
        deviceId != null &&
        (last == null || now.difference(last) >= _engineRecoveryInterval);
    // Off, never "Protected": nothing is being carried. The server-side
    // credential is kept, so a reconnect reuses it. "Reconnecting" only when
    // one follows: once per interval, and the second stall said it anyway.
    final AppText text = ref.read(appTextProvider);
    await _endTunnel(
      reason: retry ? text.errorTunnelStopped : text.errorTunnelNoTraffic,
      revokeOnServer: false,
    );
    if (!ref.mounted || !retry) {
      return;
    }
    _lastEngineRecovery = now;
    // Dead after carrying traffic is how a throttled address looks; the
    // next route's tunnel may not be. See moveApiRouteProvider.
    ref.read(moveApiRouteProvider)();
    await connect(deviceId);
  }

  DateTime _lastTunnelCheckAway = DateTime.fromMillisecondsSinceEpoch(0);

  Future<void> _checkTunnel() async {
    if (!state.tunnelEstablished) {
      _stopWatchingTunnel();
      return;
    }
    // Two calls into Android every two seconds, all night, mostly keep the
    // screen right. Out of sight, every thirty: a dead engine is still taken
    // down and tried again within a minute (two readings) while the person
    // uses other apps, and the app's return checks at once (_watchTunnel).
    if (!ref.read(trafficCheckMeaningfulProvider)()) {
      final DateTime now = DateTime.now();
      if (now.difference(_lastTunnelCheckAway) <
          backgroundTunnelCheckInterval) {
        return;
      }
      _lastTunnelCheckAway = now;
    }
    bool? up;
    try {
      // Another app's VPN counts as this tunnel gone: taking consent is how
      // another VPN app replaces it.
      final LocalProxy? proxy = state.localProxy;
      up = proxy != null
          ? await ref.read(loopbackPortProbeProvider)(proxy.port)
          : switch (await _tunnel.activeVpn()) {
              VpnOwner.own => true,
              VpnOwner.none || VpnOwner.other => false,
              null => null,
            };
    } catch (_) {
      up = null;
    }
    if (!ref.mounted || _tunnelWatch == null) {
      return;
    }
    if (up != false) {
      _tunnelMissingReadings = 0;
      if (up == true) {
        await _checkEngine();
      }
      return;
    }
    _tunnelMissingReadings++;
    // A disconnect in progress takes the tunnel down on purpose.
    if (_tunnelMissingReadings < 2 ||
        state.isSubmitting ||
        !state.tunnelEstablished) {
      return;
    }
    _stopWatchingTunnel();
    unawaited(_forgetConnection());
    // Gone without this app taking it down: another VPN app connected, or it
    // was disconnected from Android's settings. That is the end of the
    // connection, not a fault to retry -- somebody chose a different VPN --
    // so it is taken down the rest of the way and the screen says Off. It used to stop at "Not protected" with the
    // client still registered, which read as Nebula still being on.
    state = state.copyWith(
      tunnelEstablished: false,
      tunnelEstablishedAt: () => null,
      sanctionsOnly: false,
      localProxy: () => null,
    );
    final String? deviceId = _connectedDeviceId ?? _storedDeviceId();
    if (deviceId != null) {
      // The local tunnel is already gone, so this only revokes and clears.
      await disconnect(deviceId);
    }
    if (ref.mounted && state.isConnected) {
      // The revoke did not go through -- offline, most likely. Off all the
      // same: nothing is tunnelling, and the client is revoked the next time
      // this device connects or the server prunes it.
      state = state.copyWith(
        isSubmitting: false,
        peer: () => null,
        xrayClient: () => null,
        connectedServerCode: () => null,
        activeProtocolCode: () => null,
        activeProfileCode: () => null,
        actionErrorMessage: () => null,
      );
    }
  }

  String? _storedDeviceId() {
    try {
      return ref.read(deviceIdStoreProvider).read();
    } catch (_) {
      return null;
    }
  }

  /// Whether a WireGuard tunnel just brought up has heard from its server.
  ///
  /// Waits through three of WireGuard's handshake attempts, which are five
  /// seconds apart. A platform that cannot tell is taken at its word that
  /// the tunnel is up, as it always was.
  Future<bool> _serverAnswered(int attempt) async {
    final Duration step = ref.read(tunnelSettleStepProvider);
    for (int waited = 0; waited < _handshakeWaitSteps; waited++) {
      // The longest wait in a connect, and so the likeliest place for Cancel.
      if (!ref.mounted || _cancelled(attempt)) {
        return false;
      }
      if (await _tunnel.hasHandshake() != false) {
        return true;
      }
      await Future<void>.delayed(step);
    }
    return false;
  }

  /// Whether a request gets out through a tunnel just brought up.
  ///
  /// Three tries, each with its own deadline: the first request over a new
  /// tunnel can be slow, through a CDN especially.
  Future<bool> _tunnelCarriesTraffic(
    int attempt, {
    bool viaProxy = true,
  }) async {
    final Future<bool> Function(LocalProxy?) carries = ref.read(
      tunnelCarriesTrafficProvider,
    );
    Future<bool> probe() => carries(viaProxy ? _tunnelProxy : null);
    for (int tried = 0; tried < 3; tried++) {
      if (!ref.mounted || _cancelled(attempt)) {
        return false;
      }
      final Stopwatch took = Stopwatch()..start();
      final bool answered = await probe();
      if (!answered && took.elapsed >= _probeGaveUp) {
        // It waited out its whole deadline: nothing is there. Trying twice
        // more only adds the same wait again (a dead server sat at
        // Connecting for 79 s). A quick failure -- the engine still coming
        // up -- is still tried again.
        return false;
      }
      if (answered) {
        // And once more: a throttled address carries the first request and
        // stalls everything after it (measured from Iran, 2026-10-06), so
        // one answer does not say the tunnel stays up. And quickly: raw
        // TCP+TLS to a throttled address answered this in 4.8-7.2 s while a
        // 5 MB download got nothing, where working tunnels took 0.6-2.2 s
        // (on the phone, 2026-10-17) -- "Protected" over a tunnel that slow
        // is the screen saying connected while nothing loads.
        return await probe().timeout(_confirmWithin, onTimeout: () => false);
      }
    }
    return false;
  }

  /// A failed probe this slow timed out rather than being refused.
  static const Duration _probeGaveUp = Duration(seconds: 6);

  /// How long the second, confirming request through a new tunnel may take.
  static const Duration _confirmWithin = Duration(milliseconds: 3500);

  /// Where the per-protocol test sends its request: v2ray's own default, a
  /// tiny empty answer from a host that is reachable wherever the tunnel is.
  static const String _delayProbeUrl = 'https://www.gstatic.com/generate_204';

  /// 10 MB, more than ten seconds of most lines in Iran: the speed test
  /// reads what arrives in ten seconds.
  static const String _speedProbeUrl =
      'https://speed.cloudflare.com/__down?bytes=10000000';

  Future<String> _probeConfig(
    XrayClientResult credential,
    AdvancedSettings settings,
  ) async {
    await ref.read(echServerRefreshProvider)(echConfigListFor(credential));
    return credential.transport == 'hysteria'
        ? renderHysteriaDelayProbeConfigJson(
            credential,
            localProxy: await LocalProxy.generate(),
          )
        : renderXrayDelayProbeConfigJson(credential, settings: settings);
  }

  /// Tests every profile of the selected server with a real request through
  /// it, like v2ray's "real delay", and records each result as it lands.
  ///
  /// A port check is not enough and was the reason for this: gRPC routed
  /// through nginx answered a TCP connect and carried nothing. Each Xray
  /// profile is dialled exactly as Connect would dial it. Hysteria2 is
  /// measured through the reference client, started for the test, because
  /// Xray drops its obfuscation; WireGuard through Xray's own WireGuard
  /// client, with this device's key.
  ///
  /// Tests the credentials already on this phone, as v2ray tests the
  /// configs it holds, and asks the server only for a profile it has never
  /// been given one for. Those requests go one at a time -- the server
  /// handles a device's requests in turn, so sent together the later ones
  /// time out and read as unreachable -- while the measurements run all at
  /// once: one after another, every unreachable profile cost its full
  /// timeout in turn and a server took over a minute. A credential requested
  /// here is kept and saved, as a connect would.
  ///
  /// ponytail: a saved credential revoked since reads as unreachable until
  /// the next connect replaces it. Re-request on a failed saved credential if
  /// that ever misleads anyone.
  ///
  /// [server] is the one the picker is showing, which need not be the
  /// selected one yet: with only the selection, a first-time user -- who has
  /// not pressed "Use" -- pressed Test and nothing happened. Seen on
  /// Windows.
  Future<void> pingProtocols(String deviceId, {AvailableServer? server}) async {
    server ??= state.selectedServer;
    if (server == null || state.pinging) {
      return;
    }
    state = state.copyWith(
      pinging: true,
      protocolDelaysServer: () => server!.code,
      protocolDelays: <String, ProtocolDelay>{
        for (final AvailableProfile profile in server.profiles)
          profile.code: const ProtocolDelay.testing(),
      },
    );
    // The list as the server gives it now. Read only at launch, a route the
    // server has changed since -- WebSocket moved onto Cloudflare -- was
    // tested where it no longer is, and read -1 until the app restarted.
    final String code = server.code;
    AvailableServer? fresh;
    try {
      final List<AvailableServer> servers = await _repository
          .listAvailableServers();
      if (!ref.mounted) {
        return;
      }
      state = state.copyWith(servers: servers);
      fresh = servers.where((AvailableServer s) => s.code == code).firstOrNull;
    } catch (_) {
      // Offline or the server unreachable: test what is already listed.
    }
    final AvailableServer tested = fresh ?? server;
    final AdvancedSettings settings = ref.read(
      advancedSettingsControllerProvider,
    );
    void record(AvailableProfile profile, ProtocolDelay delay) {
      if (!ref.mounted) {
        return;
      }
      state = state.copyWith(
        protocolDelays: <String, ProtocolDelay>{
          ...state.protocolDelays,
          profile.code: delay,
        },
      );
    }

    final List<Future<void>> measuring = <Future<void>>[];
    final List<AvailableProfile> wireguard = <AvailableProfile>[];
    final Map<AvailableProfile, XrayClientResult> answered =
        <AvailableProfile, XrayClientResult>{};
    // A few at a time: a subscription's group can hold a hundred links, and
    // each test starts an engine of its own on the phone.
    int running = 0;
    final List<Completer<void>> waiting = <Completer<void>>[];
    Future<void> slot() async {
      while (running >= 16) {
        final Completer<void> turn = Completer<void>();
        waiting.add(turn);
        await turn.future;
      }
      running++;
    }

    void release() {
      running--;
      if (waiting.isNotEmpty) {
        waiting.removeAt(0).complete();
      }
    }

    for (final AvailableProfile profile in tested.profiles) {
      if (profile.protocolCode == wireguardProtocolCode) {
        wireguard.add(profile);
        continue;
      }
      final XrayClientResult? credential = await _testCredential(
        deviceId: deviceId,
        serverCode: tested.code,
        profileCode: profile.code,
        listedPort: profile.requiredPort,
      );
      if (!ref.mounted) {
        return;
      }
      if (credential == null) {
        record(profile, const ProtocolDelay.failed());
        continue;
      }
      measuring.add(() async {
        await slot();
        try {
          await _measureOne(
            deviceId,
            tested,
            profile,
            credential,
            settings,
            record,
            answered,
          );
        } finally {
          release();
        }
      }());
    }
    if (wireguard.isNotEmpty) {
      measuring.add(
        _pingWireGuard(
          deviceId: deviceId,
          serverCode: tested.code,
          profiles: wireguard,
          record: record,
        ),
      );
    }
    await Future.wait(measuring);
    // Then the download, one protocol at a time so they do not share the
    // line, as v2rayN's latency-and-speed test: a throttled route answers
    // the delay test and stalls a transfer (Windows, 2026-10-30).
    for (final MapEntry<AvailableProfile, XrayClientResult> entry
        in answered.entries) {
      if (!ref.mounted) {
        return;
      }
      final double? megabits;
      try {
        megabits = await _xrayTunnel.measureDownload(
          await _probeConfig(entry.value, settings),
          url: _speedProbeUrl,
        );
      } catch (_) {
        continue;
      }
      if (megabits == null) {
        continue;
      }
      final int? ms = state.protocolDelays[entry.key.code]?.milliseconds;
      if (ms != null) {
        record(entry.key, ProtocolDelay.measured(ms, megabits: megabits));
      }
    }
    if (!ref.mounted) {
      return;
    }
    state = state.copyWith(pinging: false);
  }

  Future<void> _measureOne(
    String deviceId,
    AvailableServer tested,
    AvailableProfile profile,
    XrayClientResult credential,
    AdvancedSettings settings,
    void Function(AvailableProfile, ProtocolDelay) record,
    Map<AvailableProfile, XrayClientResult> answered,
  ) async {
    XrayClientResult used = credential;
    ProtocolDelay delay = await _measureXray(credential, settings);
    // Not for a link of the device's own: asked again it is the same link.
    if (delay.outcome == DelayOutcome.failed && !isOwnLinkCode(tested.code)) {
      // Once more, as the server gives the credential now. A saved one
      // can name an address the server has since given up: after its
      // IPv4 was swapped (2026-10-07), Hysteria2 -- dialled by address --
      // tested -1 while connecting, which asks afresh, worked. And UDP
      // comes and goes on Iranian networks: Hysteria2 and WireGuard
      // tested -1 and a minute later measured, while TCP never failed.
      final XrayClientResult? fresh = await _freshTestCredential(
        deviceId: deviceId,
        serverCode: tested.code,
        profileCode: profile.code,
      );
      used = fresh ?? credential;
      delay = await _measureXray(used, settings);
    }
    if (delay.outcome == DelayOutcome.measured) {
      answered[profile] = used;
    }
    record(profile, delay);
  }

  /// The credential a test uses: the one in use, else the saved one, else a
  /// fresh one from the server, which is then saved. Null when there is
  /// none -- including when the server cannot be reached, in which case
  /// nothing reached through it works either.
  Future<XrayClientResult?> _testCredential({
    required String deviceId,
    required String serverCode,
    required String profileCode,
    int? listedPort,
  }) async {
    if (state.tunnelEstablished &&
        state.connectedServerCode == serverCode &&
        state.activeProfileCode == profileCode &&
        state.xrayClient != null) {
      return state.xrayClient;
    }
    // A link of the device's own is its own credential: nothing is issued,
    // so nothing is saved -- a copy saved before a fix to how links are read
    // went on being tested -- and secure storage is not touched a hundred
    // times for a subscription's group.
    if (isOwnLinkCode(serverCode)) {
      try {
        return await _repository.requestXrayClient(
          deviceId: deviceId,
          serverCode: serverCode,
          protocolProfileCode: profileCode,
        );
      } catch (_) {
        return null;
      }
    }
    final XrayCredentialStore store = ref.read(xrayCredentialStoreProvider);
    final XrayClientResult? saved = await _recalled(
      store,
      serverCode: serverCode,
      profileCode: profileCode,
    );
    // Only while it still points where the server now lists the protocol: a
    // credential issued on another route (the direct address, before the
    // route moved onto Cloudflare) would test a path the app no longer uses.
    if (saved != null && (listedPort == null || saved.port == listedPort)) {
      return saved;
    }
    return _freshTestCredential(
      deviceId: deviceId,
      serverCode: serverCode,
      profileCode: profileCode,
    );
  }

  /// A credential straight from the server, saved for next time; null when
  /// the server cannot be reached.
  Future<XrayClientResult?> _freshTestCredential({
    required String deviceId,
    required String serverCode,
    required String profileCode,
  }) async {
    final XrayCredentialStore store = ref.read(xrayCredentialStoreProvider);
    try {
      final XrayClientResult credential = await _repository.requestXrayClient(
        deviceId: deviceId,
        serverCode: serverCode,
        protocolProfileCode: profileCode,
      );
      await _remember(
        store,
        serverCode: serverCode,
        profileCode: profileCode,
        credential: credential,
      );
      return credential;
    } catch (_) {
      return null;
    }
  }

  Future<ProtocolDelay> _measureXray(
    XrayClientResult credential,
    AdvancedSettings settings,
  ) async {
    try {
      return _measure(await _probeConfig(credential, settings));
    } catch (_) {
      return const ProtocolDelay.failed();
    }
  }

  /// The device has one WireGuard peer per server, which the server hands to
  /// whichever profile asks -- so one peer and one measurement answer for
  /// every WireGuard profile. Asking again per profile was refused while the
  /// first was still being applied, and read as unreachable. The peer is
  /// revoked again afterwards, as Disconnect revokes one, unless this device
  /// is connected on it.
  Future<void> _pingWireGuard({
    required String deviceId,
    required String serverCode,
    required List<AvailableProfile> profiles,
    required void Function(AvailableProfile, ProtocolDelay) record,
  }) async {
    final bool connected =
        state.tunnelEstablished &&
        state.connectedServerCode == serverCode &&
        state.peer != null;
    ProtocolDelay delay = const ProtocolDelay.failed();
    try {
      final WireGuardKeyPair keyPair = await _currentOrNewKeyPair();
      final WireGuardPeerResult peer = connected
          ? state.peer!
          : await _repository.requestPeer(
              deviceId: deviceId,
              serverCode: serverCode,
              protocolProfileCode: profiles.first.code,
              publicKey: keyPair.publicKeyBase64,
            );
      delay = await _measure(
        renderWireGuardDelayProbeConfigJson(
          privateKeyBase64: keyPair.privateKeyBase64,
          peer: peer,
        ),
      );
      if (!connected) {
        await _repository.revokePeer(
          deviceId: deviceId,
          serverCode: serverCode,
        );
      }
    } catch (_) {
      // No peer is a failed test; a revoke that did not go through is left
      // for the server's own cleanup, not a reason to change the answer.
    }
    for (final AvailableProfile profile in profiles) {
      record(profile, delay);
    }
  }

  Future<ProtocolDelay> _measure(String config) async {
    try {
      return _delayFrom(
        await _xrayTunnel.measureDelay(config, url: _delayProbeUrl),
      );
    } catch (_) {
      return const ProtocolDelay.failed();
    }
  }

  /// Null is a platform with no way to measure; it reads as unreachable,
  /// which is what the person can act on.
  static ProtocolDelay _delayFrom(int? milliseconds) =>
      milliseconds != null && milliseconds >= 0
      ? ProtocolDelay.measured(milliseconds)
      : const ProtocolDelay.failed();

  /// Replaces a connection raised from a saved credential with a fresh one,
  /// once the server can be reached again.
  ///
  /// Measured on a phone: a tunnel raised while the phone had no network at
  /// all -- connect-on-launch in airplane mode -- never carried traffic after
  /// the network came back, while one raised online survived the same drop.
  /// Reconnecting as soon as the server answers again fixes that, and swaps a
  /// credential nobody confirmed for one the server just issued.
  ///
  /// Does nothing for a connection the server already issued, or while the
  /// server stays unreachable -- then the saved credential is all there is.
  Future<void> refreshAfterOffline(String? deviceId) async {
    if (deviceId == null ||
        !state.fromSavedCredential ||
        !state.tunnelEstablished ||
        state.isSubmitting) {
      return;
    }
    await disconnect(deviceId);
    await connect(deviceId);
  }

  Future<void> disconnect(String deviceId) async {
    final String? serverCode = state.connectedServerCode;
    if (serverCode == null) {
      return;
    }
    final String? protocolCode = state.activeProtocolCode;
    final bool isXray = protocolCode != wireguardProtocolCode;

    state = state.copyWith(isSubmitting: true, actionErrorMessage: () => null);
    // Best-effort: tear down the local tunnel first so traffic stops
    // flowing before a WireGuard peer is revoked, but a failure here must
    // not block revoking it.
    if (state.tunnelEstablished) {
      try {
        if (isXray) {
          await _xrayTunnel.disconnect();
        } else {
          await _tunnel.disconnect();
        }
        // Removing the VPN interface makes Android briefly report no
        // active network while it switches the default route back to
        // WiFi/cellular -- confirmed live: the very next call (the revoke
        // request below) would otherwise race that switch and fail with a
        // spurious "you're offline", even though the underlying network
        // was fine seconds later. This settling delay gives the OS the
        // brief window it needs before the revoke call below runs.
        await Future<void>.delayed(const Duration(milliseconds: 600));
        await _forgetConnection();
      } catch (_) {
        // Fall through to the server-side revoke regardless.
      }
    }
    final String? profileCode = state.activeProfileCode;
    if (isXray && profileCode == null) {
      // An Xray connection should always have set activeProfileCode
      // alongside activeProtocolCode -- treat this as already disconnected
      // rather than sending a malformed revoke.
      state = state.copyWith(
        isSubmitting: false,
        peer: () => null,
        xrayClient: () => null,
        connectedServerCode: () => null,
        activeProtocolCode: () => null,
        activeProfileCode: () => null,
        tunnelEstablished: false,
        tunnelEstablishedAt: () => null,
        sanctionsOnly: false,
        localProxy: () => null,
      );
      return;
    }
    try {
      // An Xray credential is kept: the server hands the same one back on the
      // next connect, and the saved copy is what an offline connect uses. It
      // is revoked on sign-out, by an admin, or when the account's access or
      // data runs out -- all on the server, for every credential the device
      // holds.
      if (!isXray) {
        await runGuarded(
          ref,
          () => _repository.revokePeer(
            deviceId: deviceId,
            serverCode: serverCode,
          ),
        );
      }
      state = state.copyWith(
        isSubmitting: false,
        peer: () => null,
        xrayClient: () => null,
        connectedServerCode: () => null,
        activeProtocolCode: () => null,
        activeProfileCode: () => null,
        tunnelEstablished: false,
        tunnelEstablishedAt: () => null,
        sanctionsOnly: false,
        localProxy: () => null,
      );
    } catch (error) {
      state = state.copyWith(
        isSubmitting: false,
        actionErrorMessage: () =>
            userFacingErrorMessage(error, ref.read(appTextProvider)),
      );
    }
  }

  /// Looks up the currently selected server's profile to find which
  /// protocol it provisions -- the picker only tracks profile codes, not
  /// protocol codes, so this is the one place that needs to cross-reference
  /// [DevicesState.selectedServer].
  String? _protocolCodeFor(String profileCode) {
    for (final AvailableProfile profile
        in state.selectedServer?.profiles ?? const <AvailableProfile>[]) {
      if (profile.code == profileCode) {
        return profile.protocolCode;
      }
    }
    return null;
  }

  /// Reuses this install's existing WireGuard identity if one was already
  /// generated, rather than minting a new key pair (and therefore a new
  /// peer identity) on every connect attempt.
  Future<WireGuardKeyPair> _currentOrNewKeyPair() async {
    final String? storedPrivateKey = await _keyStore.readPrivateKey();
    if (storedPrivateKey != null) {
      return _keyGenerator.fromStoredPrivateKey(storedPrivateKey);
    }
    final WireGuardKeyPair generated = await _keyGenerator.generate();
    await _keyStore.writePrivateKey(generated.privateKeyBase64);
    return generated;
  }
}

/// How often a tunnel reported as up is checked for still being there.
/// Checks which resolver can fetch Cloudflare's ECH keys before a tunnel
/// that needs them. Replaced in tests, which have no network to ask.
final echServerRefreshProvider = Provider<Future<void> Function(String?)>(
  (Ref ref) => refreshEchServer,
);

/// How often [DevicesController] checks the tunnel while the app is out of
/// sight: often enough to bring a dead engine back within a minute, rarely
/// enough not to keep a sleeping phone busy.
const Duration backgroundTunnelCheckInterval = Duration(seconds: 30);

final tunnelWatchIntervalProvider = Provider<Duration>(
  (Ref ref) => const Duration(seconds: 2),
);

/// How often an Xray or Hysteria2 tunnel is asked to carry one small request.
/// See DevicesController._checkTraffic.
final trafficCheckIntervalProvider = Provider<Duration>(
  (Ref ref) => const Duration(minutes: 1),
);

/// Whether a [dataProbeBytes] download completes through the tunnel; see
/// DevicesController._tunnelAnswers. Cloudflare's speed endpoint answered
/// from both an Iranian and a German exit (2026-10-30).
const int dataProbeBytes = 131072;
final tunnelMovesDataProvider =
    Provider<Future<bool> Function(LocalProxy? through)>(
      (Ref ref) => (LocalProxy? through) async {
        const String path = '/__down?bytes=$dataProbeBytes';
        if (through != null &&
            defaultTargetPlatform == TargetPlatform.android) {
          final ({int status, String body})? answer = await httpsThroughSocks(
            through,
            host: 'speed.cloudflare.com',
            path: path,
            timeout: const Duration(seconds: 12),
            // The headers come first; the default 64 KB would cut the
            // download short and fail every working tunnel.
            bodyLimit: dataProbeBytes + 4096,
          );
          return answer != null &&
              answer.status == 200 &&
              answer.body.length >= dataProbeBytes;
        }
        return _receives('https://speed.cloudflare.com$path', dataProbeBytes);
      },
    );

/// How soon the traffic watch asks again: once after a connect, and after
/// an unanswered reading. See DevicesController._checkTrafficSoon.
final trafficRecheckDelayProvider = Provider<Duration>(
  (Ref ref) => const Duration(seconds: 5),
);

/// Calls back each time the app comes back on screen, and returns how to
/// stop. Nothing where there is no app lifecycle to listen to.
final appResumedProvider = Provider<void Function() Function(void Function())>(
  (Ref ref) => (void Function() onResume) {
    try {
      return AppLifecycleListener(onResume: onResume).dispose;
    } on Object {
      return () {};
    }
  },
);

/// Whether an unanswered request says something about the tunnel.
///
/// Not on Android with the app off screen: a dozing phone may hold back a
/// backgrounded app's own requests while the tunnel carries everyone else's,
/// and a VPN that turned itself off overnight would be worse than the fault
/// this looks for. Untested on a phone either way, so it is not relied on.
final trafficCheckMeaningfulProvider = Provider<bool Function()>(
  (Ref ref) =>
      () =>
          defaultTargetPlatform != TargetPlatform.android ||
          WidgetsBinding.instance.lifecycleState == AppLifecycleState.resumed,
);

/// How often a connected tunnel checks that its access has not ended. See
/// DevicesController._checkAccess.
final accessCheckIntervalProvider = Provider<Duration>(
  (Ref ref) => const Duration(seconds: 30),
);

/// The step used while waiting for a stopped tunnel to be gone.
final tunnelSettleStepProvider = Provider<Duration>(
  (Ref ref) => const Duration(milliseconds: 200),
);

/// One request for the protocol test's page, sent as any app's would be --
/// so, with a tunnel up, through it. True when it came back.
///
/// [through] is the tunnel's local proxy when this app started it. On
/// Android the request goes through that: the app is outside its own tunnel,
/// so a plain request would answer whenever the phone is online. See
/// [answersThroughSocks].
final tunnelCarriesTrafficProvider =
    Provider<Future<bool> Function(LocalProxy? through)>(
      (Ref ref) =>
          (LocalProxy? through) =>
              through != null && defaultTargetPlatform == TargetPlatform.android
              ? answersThroughSocks(through)
              : _answers(DevicesController._delayProbeUrl),
    );

/// Whether the tunnel's resolver answers a DNS question sent through the
/// tunnel's proxy over UDP. Android only: elsewhere this app's own traffic is
/// inside the tunnel, so the plain request already takes the apps' path.
final tunnelResolvesProvider =
    Provider<Future<bool> Function(LocalProxy through, InternetAddress dns)>(
      (Ref ref) =>
          (LocalProxy through, InternetAddress dns) async =>
              defaultTargetPlatform != TargetPlatform.android ||
              await resolvesThroughSocks(through, dns),
    );

/// Which step to the server fails, from outside the tunnel. See
/// [checkServerReach].
final serverReachProvider = Provider<ServerReachCheck>(
  (Ref ref) => checkServerReach,
);

/// Whether this device reaches the internet at all, with no tunnel up:
/// asked of the address Android itself uses to decide a network is online,
/// so it answers wherever a phone shows it is connected.
final deviceOnlineProvider = Provider<Future<bool> Function()>(
  (Ref ref) =>
      () => _anyAnswers(<String>[
        'https://connectivitycheck.gstatic.com/generate_204',
        // Not Google: on a filtered day Google alone timed out while the
        // network worked, and the app told a connected phone it was offline
        // (2026-10-18).
        'https://checkip.amazonaws.com/',
      ]),
);

/// Whether any of [urls] answers; asked together, so the slowest does not
/// decide.
Future<bool> _anyAnswers(List<String> urls) async {
  final Completer<bool> answer = Completer<bool>();
  int left = urls.length;
  for (final String url in urls) {
    unawaited(
      _answers(url).then((bool ok) {
        left--;
        if (!answer.isCompleted && (ok || left == 0)) {
          answer.complete(ok);
        }
      }),
    );
  }
  return answer.future;
}

Future<bool> _receives(String url, int bytes) async {
  final HttpClient client = HttpClient()
    ..connectionTimeout = const Duration(seconds: 5);
  try {
    return await () async {
      final HttpClientResponse response = await (await client.getUrl(
        Uri.parse(url),
      )).close();
      int got = 0;
      await for (final List<int> chunk in response) {
        got += chunk.length;
      }
      return response.statusCode == 200 && got >= bytes;
    }().timeout(const Duration(seconds: 12));
  } on Object {
    return false;
  } finally {
    client.close(force: true);
  }
}

Future<bool> _answers(String url) async {
  final HttpClient client = HttpClient()
    ..connectionTimeout = const Duration(seconds: 5);
  try {
    final int status = await () async {
      final HttpClientResponse response = await (await client.getUrl(
        Uri.parse(url),
      )).close();
      await response.drain<void>();
      return response.statusCode;
    }().timeout(const Duration(seconds: 6));
    return status < 400;
  } on Object {
    return false;
  } finally {
    client.close(force: true);
  }
}

/// When a tunnel picked back up by a reopened app began, and from which
/// counter readings its figures count.
typedef AdoptedSession = ({DateTime? since, TunnelTraffic? baseline});

/// Decides [AdoptedSession] for a running tunnel and the record it was
/// started from.
///
/// A restore newer than the record means Android started the tunnel again
/// underneath it -- after a restart or an update -- so the session began then,
/// with the engine's counters at zero. Otherwise the record's own start
/// stands. A start in the future is a clock that moved, and is unknown.
AdoptedSession adoptedSession(
  ConnectionRecord record, {
  required DateTime? restoredAt,
  required DateTime now,
}) {
  final DateTime? recorded = record.establishedAt;
  if (restoredAt != null &&
      !restoredAt.isAfter(now) &&
      (recorded == null || restoredAt.isAfter(recorded))) {
    return (
      since: restoredAt,
      baseline: const TunnelTraffic(rxBytes: 0, txBytes: 0),
    );
  }
  if (recorded == null || recorded.isAfter(now)) {
    return (since: null, baseline: null);
  }
  return (since: recorded, baseline: record.trafficBaseline);
}

final devicesControllerProvider =
    NotifierProvider<DevicesController, DevicesState>(DevicesController.new);
