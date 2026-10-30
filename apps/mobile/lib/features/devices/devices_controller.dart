import 'dart:async';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/account/account_repository.dart';
import '../../core/auth/auth_notifier.dart';
import '../../core/auth/auth_state.dart';
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

part 'devices_controller_connecting.dart';
part 'devices_controller_credentials.dart';
part 'devices_controller_health.dart';
part 'devices_controller_speed.dart';

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

const WireGuardKeyGenerator _keyGenerator = WireGuardKeyGenerator();

const Duration _engineRecoveryInterval = Duration(minutes: 2);

String _inboundOf(String profileCode) => profileCode.endsWith('-adblock')
    ? profileCode.substring(0, profileCode.length - '-adblock'.length)
    : profileCode;

/// At most this many protocols per Automatic connect. A protocol that
/// carries nothing is found out in about 20 s; a server offering twelve
/// would otherwise keep somebody at Connecting for four minutes.
const int _automaticTries = 4;

/// A failed probe this slow timed out rather than being refused.
const Duration _probeGaveUp = Duration(seconds: 6);

/// How long the second, confirming request through a new tunnel may take.
const Duration _confirmWithin = Duration(milliseconds: 3500);

/// Where the per-protocol test sends its request: v2ray's own default, a
/// tiny empty answer from a host that is reachable wherever the tunnel is.
const String _delayProbeUrl = 'https://www.gstatic.com/generate_204';

/// 10 MB, more than ten seconds of most lines in Iran: the speed test
/// reads what arrives in ten seconds.
const String _speedProbeUrl =
    'https://speed.cloudflare.com/__down?bytes=10000000';

/// Null is a platform with no way to measure; it reads as unreachable,
/// which is what the person can act on.
ProtocolDelay _delayFrom(int? milliseconds) =>
    milliseconds != null && milliseconds >= 0
    ? ProtocolDelay.measured(milliseconds)
    : const ProtocolDelay.failed();

/// Fields and the shared plumbing; the four concerns are mixins in the
/// part files, so each reads on its own.
abstract class _DevicesCore extends Notifier<DevicesState> {
  late ServerRepository _repository;

  late WireGuardKeyStore _keyStore;

  late TunnelController _tunnel;

  late XrayTunnelController _xrayTunnel;

  late SelectionStore _selections;

  late ConnectionRecordStore _records;

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

  DateTime? _lastCredentialRetry;

  DateTime _lastTunnelCheckAway = DateTime.fromMillisecondsSinceEpoch(0);

  // Implemented in the mixins; named here so the other parts can call them.
  Future<void> connect(String deviceId);
  Future<void> _recordProtocol(
    String serverCode,
    String profileCode,
    ProtocolOutcome outcome,
  );
  bool _cancelled(int attempt);
  Future<void> _stopLeftoverTunnel();
  Future<void> disconnect(String deviceId);
  Future<bool> _serverChangedCredential({
    required String deviceId,
    required String serverCode,
    required String profileCode,
    required XrayClientResult saved,
  });
  Future<void> _confirmWithServer({
    required String deviceId,
    required String serverCode,
    required String profileCode,
  });
  Future<void> _revokeXrayClient({
    required String deviceId,
    required String serverCode,
    required String protocolProfileCode,
  });
  Future<void> _remember(
    XrayCredentialStore store, {
    required String serverCode,
    required String profileCode,
    required XrayClientResult credential,
  });
  Future<XrayClientResult?> _recalled(
    XrayCredentialStore store, {
    required String serverCode,
    required String profileCode,
  });
  Future<void> _checkAccess();
  Future<WireGuardKeyPair> _currentOrNewKeyPair();
  void _watchTunnel();
  void _stopWatchingTunnel();
  Future<void> _endTunnel({
    required String? reason,
    required bool revokeOnServer,
  });
  String? _storedDeviceId();
  Future<bool> _serverAnswered(int attempt);
  Future<bool> _tunnelCarriesTraffic(int attempt, {bool viaProxy = true});
  Future<String> _probeConfig(
    XrayClientResult credential,
    AdvancedSettings settings,
  );
}

class DevicesController extends _DevicesCore
    with _Connecting, _Credentials, _HealthChecks, _SpeedTests {}

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

/// Whether the sign-in is still good: false once the session expired or was
/// signed out. See DevicesController._checkAccess.
final stillSignedInProvider = Provider<bool Function()>(
  (Ref ref) =>
      () => ref.read(authNotifierProvider) is AuthAuthenticated,
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
              : _answers(_delayProbeUrl),
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
