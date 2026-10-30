import 'dart:async';
import 'dart:io';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_riverpod/misc.dart' show Override;
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/account/account_repository.dart';
import 'package:nebula_mobile/core/diagnostics/server_reach.dart';
import 'package:nebula_mobile/core/free/free_mode.dart';
import 'package:nebula_mobile/core/network/api_client.dart';
import 'package:nebula_mobile/core/network/api_exception.dart';
import 'package:nebula_mobile/core/servers/server_repository.dart';
import 'package:nebula_mobile/core/settings/advanced_settings_controller.dart';
import 'package:nebula_mobile/core/settings/locale_controller.dart';
import 'package:nebula_mobile/core/settings/protection_controller.dart';
import 'package:nebula_mobile/core/storage/advanced_settings_store.dart';
import 'package:nebula_mobile/core/storage/connection_record_store.dart';
import 'package:nebula_mobile/core/storage/locale_store.dart';
import 'package:nebula_mobile/core/storage/protection_preference_store.dart';
import 'package:nebula_mobile/core/storage/protocol_history_store.dart';
import 'package:nebula_mobile/core/storage/selection_store.dart';
import 'package:nebula_mobile/core/storage/split_tunnel_store.dart';
import 'package:nebula_mobile/core/storage/storage_providers.dart';
import 'package:nebula_mobile/core/storage/tunnel_restore_store.dart';
import 'package:nebula_mobile/core/storage/wireguard_key_store.dart';
import 'package:nebula_mobile/core/storage/xray_credential_store.dart';
import 'package:nebula_mobile/core/tunnel/tunnel_traffic.dart';
import 'package:nebula_mobile/core/wireguard/tunnel_controller.dart';
import 'package:nebula_mobile/core/xray/local_proxy.dart';
import 'package:nebula_mobile/core/xray/xray_tunnel_controller.dart';
import 'package:nebula_mobile/features/devices/devices_controller.dart';
import 'package:nebula_mobile/features/devices/devices_state.dart';
import 'package:nebula_mobile/l10n/app_localizations.dart';

import '../../core/account/fake_account_repository.dart';
import 'fake_server_repository.dart';
import 'fake_tunnel_controller.dart';
import 'fake_xray_tunnel_controller.dart';

const String _deviceId = 'device-1';

WireGuardPeerResult _peerResult() {
  return const WireGuardPeerResult(
    peerId: 'peer-1',
    assignedAddress: '10.77.0.2',
    serverPublicKey: 'SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS=',
    listenPort: 51820,
    publicEndpoint: 'vps1.example.test:51820',
    clientDns: '10.77.0.1',
    clientAllowedIps: '0.0.0.0/0,::/0',
    persistentKeepaliveSeconds: 25,
  );
}

XrayClientResult _xrayClientResult() {
  return const XrayClientResult(
    clientId: 'client-1',
    uuid: 'a1b2c3d4-0000-0000-0000-000000000000',
    serverAddress: 'ams-1.example.test',
    port: 443,
    sni: 'ams-1.example.test',
    transport: 'xhttp',
    transportSecurity: 'tls',
    adBlock: false,
    path: '/xhttp-path',
  );
}

XrayClientResult _hysteriaClientResult() {
  return const XrayClientResult(
    clientId: 'client-2',
    uuid: 'b2c3d4e5-0000-0000-0000-000000000000',
    serverAddress: 'ams-3.example.test',
    port: 8450,
    sni: 'ams-3.example.test',
    transport: 'hysteria',
    transportSecurity: 'tls',
    adBlock: false,
  );
}

const AvailableServer _wireGuardOnlyServer = AvailableServer(
  code: 'ams-1',
  displayName: 'Amsterdam 1',
  publicHost: 'ams-1.example.test',
  profiles: <AvailableProfile>[
    AvailableProfile(
      code: 'wg-default',
      displayName: 'WireGuard default',
      protocolId: 'protocol-1',
      protocolCode: 'wireguard',
      adBlock: false,
    ),
  ],
);

const AvailableServer _xrayOnlyServer = AvailableServer(
  code: 'ams-2',
  displayName: 'Amsterdam 2',
  publicHost: 'ams-2.example.test',
  profiles: <AvailableProfile>[
    AvailableProfile(
      code: 'vless-xhttp-tls',
      displayName: 'VLESS XHTTP TLS',
      protocolId: 'protocol-2',
      protocolCode: 'vless',
      adBlock: false,
    ),
  ],
);

// Five Xray protocols: more than Automatic tries in one connect.
final AvailableServer _manyXrayServer = AvailableServer(
  code: 'ams-5',
  displayName: 'Amsterdam 5',
  publicHost: 'ams-5.example.test',
  profiles: <AvailableProfile>[
    for (final String code in <String>[
      'vless-a-tls',
      'vless-b-tls',
      'vless-c-tls',
      'vless-d-tls',
      'vless-e-tls',
    ])
      AvailableProfile(
        code: code,
        displayName: code,
        protocolId: 'protocol-2',
        protocolCode: 'vless',
        adBlock: false,
      ),
  ],
);

// Hysteria2 is its own protocol code (not "vless"), confirming the
// controller's dispatch routes any non-WireGuard protocol through the Xray
// path rather than special-casing "vless" alone.
const AvailableServer _hysteriaOnlyServer = AvailableServer(
  code: 'ams-3',
  displayName: 'Amsterdam 3',
  publicHost: 'ams-3.example.test',
  profiles: <AvailableProfile>[
    AvailableProfile(
      code: 'hysteria2',
      displayName: 'Hysteria2',
      protocolId: 'protocol-3',
      protocolCode: 'hysteria2',
      adBlock: false,
    ),
  ],
);

({
  ProviderContainer container,
  FakeServerRepository repository,
  InMemoryWireGuardKeyStore keyStore,
  FakeTunnelController tunnel,
  FakeXrayTunnelController xrayTunnel,
  InMemorySelectionStore selections,
  InMemorySplitTunnelStore splitTunnel,
  InMemoryProtectionStore protection,
  InMemoryAdvancedSettingsStore advanced,
})
_harness({
  InMemorySelectionStore? selections,
  Duration? watchInterval,
  InMemoryConnectionRecordStore? records,
  Future<bool> Function(int port)? portProbe,
  Duration? accessInterval,
  FakeAccountRepository? accounts,
  InMemoryTunnelRestoreStore? restores,
  Future<bool> Function(LocalProxy?)? tunnelCarries,
  Future<bool> Function(LocalProxy, InternetAddress)? tunnelResolves,
  bool Function()? moveRoute,
  Future<bool> Function()? online,
  ServerReachCheck? reach,
  Duration? trafficInterval,
  Duration? trafficRecheck,
  Future<bool> Function(LocalProxy?)? tunnelMovesData,
  bool trafficMeaningful = true,
  bool Function()? appInFront,
  List<void Function()>? onResume,
  ServerRepository? servers,
  bool freeMode = false,
}) {
  final FakeServerRepository repository = FakeServerRepository();
  final InMemoryWireGuardKeyStore keyStore = InMemoryWireGuardKeyStore();
  final FakeTunnelController tunnel = FakeTunnelController();
  final FakeXrayTunnelController xrayTunnel = FakeXrayTunnelController();
  final InMemorySelectionStore selectionStore =
      selections ?? InMemorySelectionStore();
  final InMemorySplitTunnelStore splitTunnelStore = InMemorySplitTunnelStore();
  final InMemoryProtectionStore protectionStore = InMemoryProtectionStore();
  final InMemoryAdvancedSettingsStore advancedStore =
      InMemoryAdvancedSettingsStore();
  final ProviderContainer container = ProviderContainer(
    overrides: <Override>[
      serverRepositoryProvider.overrideWithValue(servers ?? repository),
      storedFreeModeProvider.overrideWithValue(freeMode),
      // Read back through the container where a test needs it: adding it to
      // the harness record would mean spelling the record's type out again
      // in every group that takes one.
      xrayCredentialStoreProvider.overrideWithValue(
        InMemoryXrayCredentialStore(),
      ),
      wireGuardKeyStoreProvider.overrideWithValue(keyStore),
      tunnelControllerProvider.overrideWithValue(tunnel),
      xrayTunnelControllerProvider.overrideWithValue(xrayTunnel),
      echServerRefreshProvider.overrideWithValue((String? _) async {}),
      selectionStoreProvider.overrideWithValue(selectionStore),
      // Each protocol's record, which Automatic orders by; preferences
      // otherwise.
      protocolHistoryStoreProvider.overrideWithValue(
        InMemoryProtocolHistoryStore(),
      ),
      // Split tunnelling is read at connect time, and its store reaches
      // SharedPreferences. Without this the connect throws before the
      // tunnel is ever asked to come up.
      splitTunnelStoreProvider.overrideWithValue(splitTunnelStore),
      // Error messages are written in the app's language, and the chosen
      // language is read from a store that reaches SharedPreferences too.
      localeStoreProvider.overrideWithValue(InMemoryLocaleStore()),
      // The route list is derived from the protection preferences at connect
      // time, and that store reaches SharedPreferences too.
      protectionPreferenceStoreProvider.overrideWithValue(protectionStore),
      // The Xray config is built from these at connect time, and the store
      // behind them reaches SharedPreferences.
      advancedSettingsStoreProvider.overrideWithValue(advancedStore),
      // Waiting out a stopped tunnel is real time on a phone and none here.
      tunnelSettleStepProvider.overrideWithValue(Duration.zero),
      // A fixed proxy rather than a bound socket per connect.
      localProxyFactoryProvider.overrideWithValue(
        () async => const LocalProxy(
          port: 20443,
          username: 'n0011223344556677',
          password: '00112233445566778899aabbccddeeff',
        ),
      ),
      // What a tunnel came up on is kept in secure storage, which is a
      // platform channel here.
      connectionRecordStoreProvider.overrideWithValue(
        records ?? InMemoryConnectionRecordStore(),
      ),
      // Local proxy mode's account lives in secure storage, and whether its
      // port is open is a real socket; neither belongs in a unit test.
      localProxyAccountStoreProvider.overrideWithValue(
        InMemoryLocalProxyAccountStore(),
      ),
      loopbackPortProbeProvider.overrideWithValue(
        portProbe ?? (int port) async => false,
      ),
      if (watchInterval != null)
        tunnelWatchIntervalProvider.overrideWithValue(watchInterval),
      // A connected tunnel asks the account whether its allowance is spent.
      // Unset, the fake has no account and every answer is a failure, which
      // the check ignores.
      accountRepositoryProvider.overrideWithValue(
        accounts ?? FakeAccountRepository(),
      ),
      if (accessInterval != null)
        accessCheckIntervalProvider.overrideWithValue(accessInterval),
      if (trafficInterval != null)
        trafficCheckIntervalProvider.overrideWithValue(trafficInterval),
      // Out of the way unless a test is about it.
      trafficRecheckDelayProvider.overrideWithValue(
        trafficRecheck ?? const Duration(hours: 1),
      ),
      // No real download in a unit test.
      tunnelMovesDataProvider.overrideWithValue(
        tunnelMovesData ?? (_) async => true,
      ),
      // No app lifecycle in a unit test.
      trafficCheckMeaningfulProvider.overrideWithValue(
        appInFront ?? () => trafficMeaningful,
      ),
      appResumedProvider.overrideWithValue((void Function() callback) {
        final List<void Function()> listeners = onResume ?? <void Function()>[];
        listeners.add(callback);
        return () => listeners.remove(callback);
      }),
      tunnelRestoreStoreProvider.overrideWithValue(
        restores ?? InMemoryTunnelRestoreStore(),
      ),
      // A real request otherwise; a tunnel that carries traffic unless a
      // test says it does not.
      tunnelCarriesTrafficProvider.overrideWithValue(
        tunnelCarries ?? (_) async => true,
      ),
      tunnelResolvesProvider.overrideWithValue(
        tunnelResolves ?? (_, _) async => true,
      ),
      // The API's other routes; none unless a test gives one.
      moveApiRouteProvider.overrideWithValue(moveRoute ?? () => false),
      // A real request otherwise; online unless a test says not.
      deviceOnlineProvider.overrideWithValue(online ?? () async => true),
      // Real connections otherwise; the server reachable unless a test says
      // otherwise.
      serverReachProvider.overrideWithValue(
        reach ?? (XrayClientResult _) async => ServerReach.reachable,
      ),
    ],
  );
  return (
    container: container,
    repository: repository,
    keyStore: keyStore,
    tunnel: tunnel,
    xrayTunnel: xrayTunnel,
    selections: selectionStore,
    splitTunnel: splitTunnelStore,
    protection: protectionStore,
    advanced: advancedStore,
  );
}

/// One of everything, for the per-protocol test: two VLESS profiles, one
/// Hysteria2, and two WireGuard profiles sharing the device's one peer.
const AvailableServer _mixedServer = AvailableServer(
  code: 'ams-9',
  displayName: 'Amsterdam 9',
  publicHost: 'ams-9.example.test',
  profiles: <AvailableProfile>[
    AvailableProfile(
      code: 'vless-ws-tls',
      displayName: 'VLESS WS',
      protocolId: 'protocol-2',
      protocolCode: 'vless',
      adBlock: false,
    ),
    AvailableProfile(
      code: 'vless-grpc-tls',
      displayName: 'VLESS gRPC',
      protocolId: 'protocol-2',
      protocolCode: 'vless',
      adBlock: false,
    ),
    AvailableProfile(
      code: 'hysteria2',
      displayName: 'Hysteria2',
      protocolId: 'protocol-3',
      protocolCode: 'hysteria2',
      adBlock: false,
    ),
    AvailableProfile(
      code: 'wg-default',
      displayName: 'WireGuard',
      protocolId: 'protocol-1',
      protocolCode: 'wireguard',
      adBlock: false,
    ),
    AvailableProfile(
      code: 'wg-adblock',
      displayName: 'WireGuard ad block',
      protocolId: 'protocol-1',
      protocolCode: 'wireguard',
      adBlock: true,
    ),
  ],
);

/// A network the way the app meets one in Iran: one switch per hostile
/// condition of roadmap section 74. A connection is described by the Xray
/// config the app writes for it, so the model judges exactly what the app
/// would send -- the address it dials, the TLS name it shows, UDP or not.
class _HostileNetwork {
  /// UDP blocked or throttled to nothing: Hysteria2 is UDP-only.
  bool udpBlocked = false;

  /// Addresses and TLS names that are dropped: the server's own IP, a
  /// filtered SNI, a blocked CDN address.
  final Set<String> blocked = <String>{};

  /// Random loss the size of one attempt: each connection's first try is
  /// lost, its second gets through.
  bool firstTryLost = false;
  final Set<String> _tried = <String>{};

  bool carries(String? config) {
    if (config == null) {
      return false;
    }
    if (udpBlocked && config.contains('nebulaHysteriaConfig')) {
      return false;
    }
    if (blocked.any((String name) => config.contains('"$name"'))) {
      return false;
    }
    // By the credential in use: a test config also carries a fresh local
    // port each time, which is not a different connection.
    final String key = <String>[
      'b2c3d4e5',
      'c3d4e5f6',
      'd4e5f6a7',
    ].firstWhere(config.contains, orElse: () => config);
    if (firstTryLost && _tried.add(key)) {
      return false;
    }
    return true;
  }
}

/// A server offering one protocol of each kind the network treats
/// differently: UDP and raw TLS to the server's own address, WebSocket
/// through the CDN.
const AvailableServer _ir1 = AvailableServer(
  code: 'ir-1',
  displayName: 'Iran test',
  publicHost: 'direct.example.test',
  profiles: <AvailableProfile>[
    AvailableProfile(
      code: 'hysteria2',
      displayName: 'Hysteria2',
      protocolId: 'protocol-3',
      protocolCode: 'hysteria2',
      adBlock: false,
    ),
    AvailableProfile(
      code: 'vless-tcp-tls',
      displayName: 'VLESS TCP',
      protocolId: 'protocol-2',
      protocolCode: 'vless',
      adBlock: false,
    ),
    AvailableProfile(
      code: 'vless-ws-tls',
      displayName: 'VLESS WebSocket',
      protocolId: 'protocol-2',
      protocolCode: 'vless',
      adBlock: false,
    ),
  ],
);

XrayClientResult _ir1Credential(String profile) => switch (profile) {
  'hysteria2' => const XrayClientResult(
    clientId: 'c-hy',
    uuid: 'b2c3d4e5-0000-0000-0000-000000000000',
    serverAddress: 'direct.example.test',
    port: 8450,
    sni: 'direct.example.test',
    transport: 'hysteria',
    transportSecurity: 'tls',
    adBlock: false,
  ),
  'vless-tcp-tls' => const XrayClientResult(
    clientId: 'c-tcp',
    uuid: 'c3d4e5f6-0000-0000-0000-000000000000',
    serverAddress: 'direct.example.test',
    port: 8449,
    sni: 'direct.example.test',
    transport: 'raw',
    transportSecurity: 'tls',
    adBlock: false,
  ),
  _ => const XrayClientResult(
    clientId: 'c-ws',
    uuid: 'd4e5f6a7-0000-0000-0000-000000000000',
    serverAddress: 'cdn.example.test',
    port: 443,
    sni: 'cdn.example.test',
    transport: 'websocket',
    transportSecurity: 'tls',
    adBlock: false,
    path: '/ws',
  ),
};

void main() {
  group('pingProtocols', () {
    Future<DevicesController> selectMixed(
      ({
        ProviderContainer container,
        FakeServerRepository repository,
        InMemoryWireGuardKeyStore keyStore,
        FakeTunnelController tunnel,
        FakeXrayTunnelController xrayTunnel,
        InMemorySelectionStore selections,
        InMemorySplitTunnelStore splitTunnel,
        InMemoryProtectionStore protection,
        InMemoryAdvancedSettingsStore advanced,
      })
      harness,
    ) async {
      harness.repository.servers = <AvailableServer>[_mixedServer];
      harness.repository.requestXrayClientResult = _xrayClientResult();
      harness.repository.requestXrayClientResultFor = (String profile) =>
          profile == 'hysteria2' ? _hysteriaClientResult() : null;
      harness.repository.requestPeerResult = _peerResult();
      await harness.container.read(devicesControllerProvider.notifier).load();
      final DevicesController notifier = harness.container.read(
        devicesControllerProvider.notifier,
      );
      notifier.selectServer('ams-9');
      return notifier;
    }

    test('reads the server list again before testing', () async {
      // A route the server changed after launch is tested as it is now.
      final harness = _harness();
      addTearDown(harness.container.dispose);
      final DevicesController notifier = await selectMixed(harness);
      harness.repository.servers = <AvailableServer>[
        AvailableServer(
          code: _mixedServer.code,
          displayName: _mixedServer.displayName,
          publicHost: _mixedServer.publicHost,
          profiles: _mixedServer.profiles
              .where((AvailableProfile p) => p.code == 'vless-ws-tls')
              .toList(),
        ),
      ];

      await notifier.pingProtocols(_deviceId);

      final DevicesState state = harness.container.read(
        devicesControllerProvider,
      );
      expect(state.servers.single.profiles, hasLength(1));
      expect(state.protocolDelays.keys, contains('vless-ws-tls'));
      expect(harness.xrayTunnel.measuredConfigs, hasLength(1));
    });

    test(
      'a saved credential from another route is replaced, not tested',
      () async {
        // Issued while the app reached the server directly, it names the
        // direct port; the server now lists the protocol on Cloudflare's.
        final harness = _harness();
        addTearDown(harness.container.dispose);
        const AvailableServer moved = AvailableServer(
          code: 'ams-7',
          displayName: 'Amsterdam 7',
          publicHost: 'ams-7.example.test',
          profiles: <AvailableProfile>[
            AvailableProfile(
              code: 'vless-ws-tls',
              displayName: 'VLESS WS',
              protocolId: 'protocol-2',
              protocolCode: 'vless',
              adBlock: false,
              requiredPort: 443,
            ),
          ],
        );
        harness.repository.servers = <AvailableServer>[moved];
        harness.repository.requestXrayClientResult = _xrayClientResult();
        await harness.container.read(devicesControllerProvider.notifier).load();
        final DevicesController notifier = harness.container.read(
          devicesControllerProvider.notifier,
        );
        notifier.selectServer('ams-7');
        final XrayClientResult stale = _xrayClientResult();
        await harness.container
            .read(xrayCredentialStoreProvider)
            .write(
              serverCode: 'ams-7',
              profileCode: 'vless-ws-tls',
              credential: XrayClientResult(
                clientId: stale.clientId,
                uuid: stale.uuid,
                serverAddress: 'direct.example.test',
                port: 8448,
                sni: stale.sni,
                transport: stale.transport,
                transportSecurity: stale.transportSecurity,
                adBlock: false,
              ),
            );

        await notifier.pingProtocols(_deviceId);

        expect(harness.repository.requestXrayClientCalls, 1);
        expect(
          harness.xrayTunnel.measuredConfigs.single,
          isNot(contains('direct.example.test')),
        );
      },
    );

    test('tests every protocol for real, each the way it connects', () async {
      // A real request per protocol, as v2ray does: gRPC through nginx once
      // answered a port check and carried nothing, which only this catches.
      final harness = _harness();
      addTearDown(harness.container.dispose);
      final DevicesController notifier = await selectMixed(harness);

      await notifier.pingProtocols(_deviceId);

      final Map<String, ProtocolDelay> delays = harness.container
          .read(devicesControllerProvider)
          .protocolDelays;
      expect(delays['vless-ws-tls']?.milliseconds, 120);
      expect(delays['vless-grpc-tls']?.outcome, DelayOutcome.measured);
      expect(delays['hysteria2']?.outcome, DelayOutcome.measured);
      expect(delays['wg-default']?.outcome, DelayOutcome.measured);
      final List<String> configs = harness.xrayTunnel.measuredConfigs;
      expect(configs, hasLength(4));
      // Hysteria2 through the reference client, which keeps Salamander;
      // WireGuard through Xray's own WireGuard client.
      expect(
        configs.where((String c) => c.contains('nebulaHysteriaConfig')),
        hasLength(1),
      );
      expect(
        configs.where((String c) => c.contains('"protocol":"wireguard"')),
        hasLength(1),
      );
      // One peer and one measurement answer for both WireGuard profiles:
      // asked again per profile, the server refused while applying the first.
      expect(delays['wg-adblock']?.outcome, DelayOutcome.measured);
      // The WireGuard peer is given back, as Disconnect gives one back.
      expect(harness.repository.requestPeerCalls, 1);
      expect(harness.repository.revokePeerCalls, 1);
      expect(
        harness.container.read(devicesControllerProvider).pinging,
        isFalse,
      );
    });

    test(
      'measures the profiles at once, not one timeout after another',
      () async {
        // One after another, every unreachable profile cost its full timeout
        // in turn, and a server of twelve took over a minute.
        final harness = _harness();
        addTearDown(harness.container.dispose);
        final DevicesController notifier = await selectMixed(harness);
        final Completer<void> gate = Completer<void>();
        harness.xrayTunnel.measureGate = gate;

        final Future<void> pinging = notifier.pingProtocols(_deviceId);
        await Future<void>.delayed(const Duration(milliseconds: 50));

        // Every profile is being measured together.
        expect(harness.xrayTunnel.measuredConfigs, hasLength(4));
        gate.complete();
        await pinging;
      },
    );

    test(
      'a credential already on the phone is tested without asking',
      () async {
        // As v2ray tests the configs it holds. Asked all at once, the server
        // takes a device's requests in turn and the later ones time out.
        final harness = _harness();
        addTearDown(harness.container.dispose);
        final DevicesController notifier = await selectMixed(harness);
        await notifier.pingProtocols(_deviceId);
        final int asked = harness.repository.requestXrayClientCalls;

        await notifier.pingProtocols(_deviceId);

        expect(harness.repository.requestXrayClientCalls, asked);
      },
    );

    test('tests the server the picker shows, before it is chosen', () async {
      // Seen on Windows: a first-time user, who had not pressed "Use" yet,
      // pressed Test and nothing happened -- it tested only the selection.
      final harness = _harness();
      addTearDown(harness.container.dispose);
      harness.repository.servers = <AvailableServer>[_mixedServer];
      harness.repository.requestXrayClientResult = _xrayClientResult();
      harness.repository.requestPeerResult = _peerResult();
      final DevicesController notifier = harness.container.read(
        devicesControllerProvider.notifier,
      );
      await notifier.load();

      await notifier.pingProtocols(_deviceId, server: _mixedServer);

      expect(harness.xrayTunnel.measuredConfigs, isNotEmpty);
      expect(
        harness.container
            .read(devicesControllerProvider)
            .protocolDelays['vless-ws-tls']
            ?.outcome,
        DelayOutcome.measured,
      );
    });

    test('credentials requested for the test are kept and saved', () async {
      final harness = _harness();
      addTearDown(harness.container.dispose);
      final DevicesController notifier = await selectMixed(harness);

      await notifier.pingProtocols(_deviceId);

      expect(harness.repository.revokeXrayClientCalls, 0);
      final InMemoryXrayCredentialStore saved =
          harness.container.read(xrayCredentialStoreProvider)
              as InMemoryXrayCredentialStore;
      expect(saved.entries, hasLength(3));
    });

    test('a saved credential that fails is tested again as the server now '
        'gives it', () async {
      // The server's IPv4 was swapped: the saved Hysteria2 credential named
      // the old address and tested -1 while connecting worked.
      final harness = _harness();
      addTearDown(harness.container.dispose);
      final DevicesController notifier = await selectMixed(harness);
      await harness.container
          .read(xrayCredentialStoreProvider)
          .write(
            serverCode: 'ams-9',
            profileCode: 'hysteria2',
            credential: const XrayClientResult(
              clientId: 'client-2',
              uuid: 'b2c3d4e5-0000-0000-0000-000000000000',
              serverAddress: '203.0.113.9',
              port: 8450,
              sni: 'ams-3.example.test',
              transport: 'hysteria',
              transportSecurity: 'tls',
              adBlock: false,
            ),
          );
      harness.xrayTunnel.delayFor = (String config) =>
          config.contains('203.0.113.9') ? -1 : 80;

      await notifier.pingProtocols(_deviceId);

      expect(
        harness.container
            .read(devicesControllerProvider)
            .protocolDelays['hysteria2']
            ?.milliseconds,
        80,
      );
      // And the fresh one is what is kept.
      expect(
        (await harness.container
                .read(xrayCredentialStoreProvider)
                .read(serverCode: 'ams-9', profileCode: 'hysteria2'))
            ?.serverAddress,
        'ams-3.example.test',
      );
    });

    test('then measures a download for each protocol that answered', () async {
      final harness = _harness();
      addTearDown(harness.container.dispose);
      final DevicesController notifier = await selectMixed(harness);
      harness.xrayTunnel.delayFor = (String _) => 90;
      harness.xrayTunnel.downloadFor = (String _) => 12.5;

      await notifier.pingProtocols(_deviceId);

      final ProtocolDelay? ws = harness.container
          .read(devicesControllerProvider)
          .protocolDelays['vless-ws-tls'];
      expect(ws?.milliseconds, 90);
      expect(ws?.megabits, 12.5);
      expect(harness.xrayTunnel.downloadConfigs, isNotEmpty);
    });

    test('a failed protocol is not downloaded through', () async {
      final harness = _harness();
      addTearDown(harness.container.dispose);
      final DevicesController notifier = await selectMixed(harness);
      harness.xrayTunnel.delayFor = (String _) => -1;
      harness.xrayTunnel.downloadFor = (String _) => 12.5;

      await notifier.pingProtocols(_deviceId);

      expect(harness.xrayTunnel.downloadConfigs, isEmpty);
    });

    test(
      'where downloads cannot be measured, the delay stands alone',
      () async {
        final harness = _harness();
        addTearDown(harness.container.dispose);
        final DevicesController notifier = await selectMixed(harness);
        harness.xrayTunnel.delayFor = (String _) => 90;

        await notifier.pingProtocols(_deviceId);

        final ProtocolDelay? ws = harness.container
            .read(devicesControllerProvider)
            .protocolDelays['vless-ws-tls'];
        expect(ws?.milliseconds, 90);
        expect(ws?.megabits, isNull);
      },
    );

    test('a request that does not come back is a failure', () async {
      final harness = _harness();
      addTearDown(harness.container.dispose);
      final DevicesController notifier = await selectMixed(harness);
      harness.xrayTunnel.delayFor = (String _) => -1;

      await notifier.pingProtocols(_deviceId);

      expect(
        harness.container
            .read(devicesControllerProvider)
            .protocolDelays['vless-ws-tls']
            ?.outcome,
        DelayOutcome.failed,
      );
    });

    test(
      'a platform that cannot measure shows the profile as unreachable',
      () async {
        final harness = _harness();
        addTearDown(harness.container.dispose);
        final DevicesController notifier = await selectMixed(harness);
        harness.xrayTunnel.delayFor = (String _) => null;

        await notifier.pingProtocols(_deviceId);

        expect(
          harness.container
              .read(devicesControllerProvider)
              .protocolDelays['vless-ws-tls']
              ?.outcome,
          DelayOutcome.failed,
        );
      },
    );

    test('no credential from the server means the test failed', () async {
      final harness = _harness();
      addTearDown(harness.container.dispose);
      final DevicesController notifier = await selectMixed(harness);
      harness.repository.requestXrayClientError =
          const NebulaConnectivityException('connection refused');

      await notifier.pingProtocols(_deviceId);

      expect(
        harness.container
            .read(devicesControllerProvider)
            .protocolDelays['vless-ws-tls']
            ?.outcome,
        DelayOutcome.failed,
      );
    });
  });
  test('the controller survives being built again', () async {
    // Changing server rebuilds it on the same object; its dependencies were
    // set once only, and the second build threw. The app drew a grey screen
    // after re-pairing (2026-10-29).
    final harness = _harness();
    addTearDown(harness.container.dispose);
    harness.container.read(devicesControllerProvider);

    harness.container.invalidate(devicesControllerProvider);

    expect(
      () => harness.container.read(devicesControllerProvider),
      returnsNormally,
    );
    await harness.container.read(devicesControllerProvider.notifier).load();
  });

  group('selection memory', _selectionMemoryTests);
  group('connect on launch', _connectOnLaunchTests);
  group('a tunnel that is not there', _tunnelHonestyTests);
  group('access that ends', _accessTests);
  group('Disconnect in the notification', _notificationDisconnectTests);
  group('a tunnel from an earlier run', _adoptionTests);
  group('local proxy mode', _localProxyModeTests);
  group('Cancel while connecting', _cancelTests);
  group('on a hostile network', _hostileNetworkTests);

  group('DevicesController.load', () {
    test('populates servers on success', () async {
      final harness = _harness();
      addTearDown(harness.container.dispose);
      harness.repository.servers = <AvailableServer>[_wireGuardOnlyServer];

      await harness.container.read(devicesControllerProvider.notifier).load();

      final DevicesState state = harness.container.read(
        devicesControllerProvider,
      );
      expect(state.loadStatus, DevicesLoadStatus.loaded);
      expect(state.servers, hasLength(1));
    });

    test('surfaces a generic message on failure', () async {
      final harness = _harness();
      addTearDown(harness.container.dispose);
      harness.repository.listError = const NebulaApiException(
        statusCode: 500,
        detail: 'Request was not accepted',
      );

      await harness.container.read(devicesControllerProvider.notifier).load();

      final DevicesState state = harness.container.read(
        devicesControllerProvider,
      );
      expect(state.loadStatus, DevicesLoadStatus.failed);
      expect(state.loadErrorMessage, isNotNull);
    });
  });

  group('DevicesController.connect (WireGuard)', () {
    test('does nothing without both a server and profile selected', () async {
      final harness = _harness();
      addTearDown(harness.container.dispose);
      final DevicesController notifier = harness.container.read(
        devicesControllerProvider.notifier,
      );

      await notifier.connect(_deviceId);

      expect(harness.repository.requestPeerCalls, 0);
    });

    test(
      'sends a freshly generated public key and stores the peer result',
      () async {
        final harness = _harness();
        addTearDown(harness.container.dispose);
        harness.repository.servers = <AvailableServer>[_wireGuardOnlyServer];
        await harness.container.read(devicesControllerProvider.notifier).load();
        final DevicesController notifier = harness.container.read(
          devicesControllerProvider.notifier,
        );
        notifier.selectServer('ams-1');
        notifier.selectProfile('wg-default');
        harness.repository.requestPeerResult = _peerResult();

        await notifier.connect(_deviceId);

        final DevicesState state = harness.container.read(
          devicesControllerProvider,
        );
        expect(harness.repository.requestPeerCalls, 1);
        expect(harness.repository.lastRequestedServerCode, 'ams-1');
        expect(harness.repository.lastRequestedPublicKey, isNotEmpty);
        expect(state.isConnected, isTrue);
        expect(state.connectedServerCode, 'ams-1');
        expect(state.activeProtocolCode, 'wireguard');
        // The generated private key must have been persisted so a later
        // connect attempt reuses this device's identity instead of minting a
        // new one.
        expect(await harness.keyStore.readPrivateKey(), isNotNull);
        // A real local tunnel was requested and brought up.
        expect(state.tunnelEstablished, isTrue);
        expect(harness.tunnel.requestPermissionCalls, 1);
        expect(harness.tunnel.connectCalls, 1);
        expect(harness.tunnel.lastConnectConfig, contains('[Interface]'));
        expect(harness.tunnel.lastConnectConfig, contains('10.77.0.2/32'));
        // The Xray path must not have been touched.
        expect(harness.xrayTunnel.connectCalls, 0);
      },
    );

    test('a server that never answers is not called Protected', () async {
      // What a network that drops WireGuard looks like from here: the
      // interface comes up, and no handshake ever completes. Measured on the
      // production phone -- every retry left over Wi-Fi, none arrived.
      final harness = _harness();
      addTearDown(harness.container.dispose);
      harness.repository.servers = <AvailableServer>[_wireGuardOnlyServer];
      await harness.container.read(devicesControllerProvider.notifier).load();
      final DevicesController notifier = harness.container.read(
        devicesControllerProvider.notifier,
      );
      notifier.selectServer('ams-1');
      notifier.selectProfile('wg-default');
      harness.repository.requestPeerResult = _peerResult();
      harness.tunnel.handshake = false;

      await notifier.connect(_deviceId);

      final DevicesState state = harness.container.read(
        devicesControllerProvider,
      );
      expect(state.isConnected, isFalse);
      expect(state.tunnelEstablished, isFalse);
      expect(state.isSubmitting, isFalse);
      // Undone on both ends, not merely hidden.
      expect(harness.tunnel.disconnectCalls, 1);
      expect(harness.repository.revokePeerCalls, 1);
      expect(state.actionErrorMessage, contains('blocking'));
      // Three attempts' worth of waiting, not one look.
      expect(harness.tunnel.hasHandshakeCalls, greaterThan(1));

      // Doing what the message says takes the message away.
      notifier.selectProfile('wg-default');
      expect(
        harness.container.read(devicesControllerProvider).actionErrorMessage,
        isNull,
      );
    });

    test('a handshake that carries nothing is undone too', () async {
      // Seen on the phone: the server's handshakes got in, the phone's
      // traffic did not, and the screen said Protected for minutes.
      final harness = _harness(tunnelCarries: (_) async => false);
      addTearDown(harness.container.dispose);
      harness.repository.servers = <AvailableServer>[_wireGuardOnlyServer];
      await harness.container.read(devicesControllerProvider.notifier).load();
      final DevicesController notifier = harness.container.read(
        devicesControllerProvider.notifier,
      );
      notifier.selectServer('ams-1');
      notifier.selectProfile('wg-default');
      harness.repository.requestPeerResult = _peerResult();
      harness.tunnel.handshake = true;

      await notifier.connect(_deviceId);

      final DevicesState state = harness.container.read(
        devicesControllerProvider,
      );
      expect(state.tunnelEstablished, isFalse);
      expect(harness.tunnel.disconnectCalls, 1);
      expect(state.actionErrorMessage, contains('blocking'));
    });

    test(
      'a server under maintenance is not connected to, and says why',
      () async {
        final harness = _harness();
        addTearDown(harness.container.dispose);
        harness.repository.servers = <AvailableServer>[
          AvailableServer(
            code: _wireGuardOnlyServer.code,
            displayName: _wireGuardOnlyServer.displayName,
            publicHost: _wireGuardOnlyServer.publicHost,
            profiles: _wireGuardOnlyServer.profiles,
            maintenance: true,
          ),
        ];
        await harness.container.read(devicesControllerProvider.notifier).load();
        final DevicesController notifier = harness.container.read(
          devicesControllerProvider.notifier,
        );
        notifier.selectServer('ams-1');
        notifier.selectProfile('wg-default');

        await notifier.connect(_deviceId);

        final DevicesState state = harness.container.read(
          devicesControllerProvider,
        );
        expect(harness.repository.requestPeerCalls, 0);
        expect(state.tunnelEstablished, isFalse);
        expect(
          state.actionErrorMessage,
          harness.container.read(appTextProvider).errorServerMaintenance,
        );
      },
    );

    test('a server that answers on a retry is connected', () async {
      final harness = _harness();
      addTearDown(harness.container.dispose);
      harness.repository.servers = <AvailableServer>[_wireGuardOnlyServer];
      await harness.container.read(devicesControllerProvider.notifier).load();
      final DevicesController notifier = harness.container.read(
        devicesControllerProvider.notifier,
      );
      notifier.selectServer('ams-1');
      notifier.selectProfile('wg-default');
      harness.repository.requestPeerResult = _peerResult();
      harness.tunnel.handshakeAnswers.addAll(<bool?>[false, false, false]);

      await notifier.connect(_deviceId);

      final DevicesState state = harness.container.read(
        devicesControllerProvider,
      );
      expect(state.tunnelEstablished, isTrue);
      expect(state.actionErrorMessage, isNull);
      expect(harness.tunnel.hasHandshakeCalls, 4);
      expect(harness.repository.revokePeerCalls, 0);
    });

    test(
      'a platform that cannot tell keeps the tunnel it brought up',
      () async {
        // Not knowing is not the same as knowing it failed.
        final harness = _harness();
        addTearDown(harness.container.dispose);
        harness.repository.servers = <AvailableServer>[_wireGuardOnlyServer];
        await harness.container.read(devicesControllerProvider.notifier).load();
        final DevicesController notifier = harness.container.read(
          devicesControllerProvider.notifier,
        );
        notifier.selectServer('ams-1');
        notifier.selectProfile('wg-default');
        harness.repository.requestPeerResult = _peerResult();
        harness.tunnel.handshake = null;

        await notifier.connect(_deviceId);

        final DevicesState state = harness.container.read(
          devicesControllerProvider,
        );
        expect(state.tunnelEstablished, isTrue);
        expect(harness.tunnel.disconnectCalls, 0);
      },
    );

    test(
      'records the peer but not a tunnel when VPN permission is denied',
      () async {
        final harness = _harness();
        addTearDown(harness.container.dispose);
        harness.repository.servers = <AvailableServer>[_wireGuardOnlyServer];
        await harness.container.read(devicesControllerProvider.notifier).load();
        final DevicesController notifier = harness.container.read(
          devicesControllerProvider.notifier,
        );
        notifier.selectServer('ams-1');
        notifier.selectProfile('wg-default');
        harness.repository.requestPeerResult = _peerResult();
        harness.tunnel.permissionGranted = false;

        await notifier.connect(_deviceId);

        final DevicesState state = harness.container.read(
          devicesControllerProvider,
        );
        // The server-side peer is still recorded -- the server did accept
        // this device, even though no local tunnel could come up.
        expect(state.isConnected, isTrue);
        expect(state.tunnelEstablished, isFalse);
        expect(state.actionErrorMessage, 'VPN permission was not granted.');
        expect(harness.tunnel.connectCalls, 0);
      },
    );

    test(
      'records the peer but not a tunnel when the platform tunnel fails to start',
      () async {
        final harness = _harness();
        addTearDown(harness.container.dispose);
        harness.repository.servers = <AvailableServer>[_wireGuardOnlyServer];
        await harness.container.read(devicesControllerProvider.notifier).load();
        final DevicesController notifier = harness.container.read(
          devicesControllerProvider.notifier,
        );
        notifier.selectServer('ams-1');
        notifier.selectProfile('wg-default');
        harness.repository.requestPeerResult = _peerResult();
        harness.tunnel.connectError = StateError('wireguard.exe failed');

        await notifier.connect(_deviceId);

        final DevicesState state = harness.container.read(
          devicesControllerProvider,
        );
        expect(state.isConnected, isTrue);
        expect(state.tunnelEstablished, isFalse);
        expect(state.actionErrorMessage, isNotNull);
      },
    );

    test(
      'reuses an existing stored key instead of generating a new one',
      () async {
        final harness = _harness();
        addTearDown(harness.container.dispose);
        await harness.keyStore.writePrivateKey(
          'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        );
        harness.repository.servers = <AvailableServer>[_wireGuardOnlyServer];
        await harness.container.read(devicesControllerProvider.notifier).load();
        final DevicesController notifier = harness.container.read(
          devicesControllerProvider.notifier,
        );
        notifier.selectServer('ams-1');
        notifier.selectProfile('wg-default');
        harness.repository.requestPeerResult = _peerResult();

        await notifier.connect(_deviceId);

        expect(
          await harness.keyStore.readPrivateKey(),
          'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        );
      },
    );

    test(
      'a failed request surfaces an error and leaves the peer unset',
      () async {
        final harness = _harness();
        addTearDown(harness.container.dispose);
        harness.repository.servers = <AvailableServer>[_wireGuardOnlyServer];
        await harness.container.read(devicesControllerProvider.notifier).load();
        final DevicesController notifier = harness.container.read(
          devicesControllerProvider.notifier,
        );
        notifier.selectServer('ams-1');
        notifier.selectProfile('wg-default');
        harness.repository.requestPeerError = const NebulaApiException(
          statusCode: 409,
          detail: 'Device already has a WireGuard peer',
        );

        await notifier.connect(_deviceId);

        final DevicesState state = harness.container.read(
          devicesControllerProvider,
        );
        expect(state.isConnected, isFalse);
        expect(state.actionErrorMessage, 'Device already has a WireGuard peer');
      },
    );
  });

  group('DevicesController.connect (Xray)', () {
    Future<DevicesController> setUpXraySelection(
      ({
        ProviderContainer container,
        FakeServerRepository repository,
        InMemoryWireGuardKeyStore keyStore,
        FakeTunnelController tunnel,
        FakeXrayTunnelController xrayTunnel,
        InMemorySelectionStore selections,
        InMemorySplitTunnelStore splitTunnel,
        InMemoryProtectionStore protection,
        InMemoryAdvancedSettingsStore advanced,
      })
      harness,
    ) async {
      harness.repository.servers = <AvailableServer>[_xrayOnlyServer];
      await harness.container.read(devicesControllerProvider.notifier).load();
      final DevicesController notifier = harness.container.read(
        devicesControllerProvider.notifier,
      );
      notifier.selectServer('ams-2');
      notifier.selectProfile('vless-xhttp-tls');
      return notifier;
    }

    test(
      'a server that cannot be reached connects on the saved credential',
      () async {
        // The whole point of the saved credential: when the API's address is
        // blocked, the tunnel is the only way back to it, and the credential
        // for that tunnel is already on the phone.
        final harness = _harness();
        addTearDown(harness.container.dispose);
        final DevicesController notifier = await setUpXraySelection(harness);
        // Saved by an earlier run whose tunnel ended without Disconnect -- a
        // drop, a reboot. Disconnect revokes, and so forgets it too.
        await harness.container
            .read(xrayCredentialStoreProvider)
            .write(
              serverCode: 'ams-2',
              profileCode: 'vless-xhttp-tls',
              credential: _xrayClientResult(),
            );
        harness.repository.requestXrayClientResult = _xrayClientResult();

        harness.repository.requestXrayClientError =
            const NebulaConnectivityException('connection refused');
        await notifier.connect(_deviceId);

        final DevicesState state = harness.container.read(
          devicesControllerProvider,
        );
        expect(state.tunnelEstablished, isTrue);
        expect(state.xrayClient?.uuid, _xrayClientResult().uuid);
        // Recorded, so the screen can say the server did not confirm this.
        expect(state.fromSavedCredential, isTrue);
        expect(state.actionErrorMessage, isNull);
      },
    );

    group('connecting from the saved credential', () {
      // The server hands each device the same credential every time, so the
      // saved one starts the tunnel without a round trip first -- what
      // v2rayNG does with its saved config. The server is asked afterwards.
      Future<DevicesController> saved(
        ({
          ProviderContainer container,
          FakeServerRepository repository,
          InMemoryWireGuardKeyStore keyStore,
          FakeTunnelController tunnel,
          FakeXrayTunnelController xrayTunnel,
          InMemorySelectionStore selections,
          InMemorySplitTunnelStore splitTunnel,
          InMemoryProtectionStore protection,
          InMemoryAdvancedSettingsStore advanced,
        })
        harness,
      ) async {
        final DevicesController notifier = await setUpXraySelection(harness);
        await harness.container
            .read(xrayCredentialStoreProvider)
            .write(
              serverCode: 'ams-2',
              profileCode: 'vless-xhttp-tls',
              credential: _xrayClientResult(),
            );
        harness.repository.requestXrayClientResult = _xrayClientResult();
        return notifier;
      }

      test('the tunnel starts before the server is asked', () async {
        final harness = _harness();
        addTearDown(harness.container.dispose);
        final DevicesController notifier = await saved(harness);
        int callsWhenStarted = -1;
        harness.xrayTunnel.onConnect = () =>
            callsWhenStarted = harness.repository.requestXrayClientCalls;

        await notifier.connect(_deviceId);
        await Future<void>.delayed(Duration.zero);

        expect(callsWhenStarted, 0);
        expect(harness.repository.requestXrayClientCalls, 1);
        final DevicesState state = harness.container.read(
          devicesControllerProvider,
        );
        expect(state.tunnelEstablished, isTrue);
        expect(state.fromSavedCredential, isFalse);
      });

      test(
        'a refusal that arrives afterwards takes it down, with the reason',
        () async {
          final harness = _harness();
          addTearDown(harness.container.dispose);
          final DevicesController notifier = await saved(harness);
          harness.repository.requestXrayClientError = const NebulaApiException(
            statusCode: 402,
            detail: 'quota',
          );

          await notifier.connect(_deviceId);
          // The refusal arrives in the background; then the disconnect runs.
          for (int i = 0; i < 60; i++) {
            if (!harness.container
                .read(devicesControllerProvider)
                .tunnelEstablished) {
              break;
            }
            await Future<void>.delayed(const Duration(milliseconds: 50));
          }

          final DevicesState state = harness.container.read(
            devicesControllerProvider,
          );
          expect(state.tunnelEstablished, isFalse);
          expect(
            state.actionErrorMessage,
            harness.container.read(appTextProvider).errorQuotaExhausted,
          );
        },
      );

      test('a sign-in that cannot be renewed leaves the tunnel up', () async {
        // Seen on the phone: the token refresh failed on a flaky network, the
        // 401 that followed was taken for a refusal, and a working tunnel
        // was dropped again and again.
        final harness = _harness();
        addTearDown(harness.container.dispose);
        final DevicesController notifier = await saved(harness);
        harness.repository.requestXrayClientError = const NebulaApiException(
          statusCode: 401,
          detail: 'Authentication was not accepted',
        );

        await notifier.connect(_deviceId);
        await Future<void>.delayed(const Duration(milliseconds: 300));

        final DevicesState state = harness.container.read(
          devicesControllerProvider,
        );
        expect(state.tunnelEstablished, isTrue);
        expect(state.actionErrorMessage, isNull);
      });

      test(
        'a saved credential that carries nothing is replaced by a new one',
        () async {
          int probes = 0;
          // The first tunnel (old credential) carries nothing; the next does.
          final harness = _harness(tunnelCarries: (_) async => ++probes > 3);
          addTearDown(harness.container.dispose);
          final DevicesController notifier = await saved(harness);
          const XrayClientResult rotated = XrayClientResult(
            clientId: 'client-1',
            uuid: 'ffffffff-0000-0000-0000-000000000000',
            serverAddress: 'ams-1.example.test',
            port: 443,
            sni: 'ams-1.example.test',
            transport: 'xhttp',
            transportSecurity: 'tls',
            adBlock: false,
            path: '/xhttp-path',
          );
          harness.repository.requestXrayClientResult = rotated;

          await notifier.connect(_deviceId);

          final DevicesState state = harness.container.read(
            devicesControllerProvider,
          );
          expect(harness.xrayTunnel.connectCalls, 2);
          expect(state.tunnelEstablished, isTrue);
          expect(state.xrayClient?.uuid, rotated.uuid);
        },
      );

      test('through Cloudflare, a tunnel that carries nothing is redialled '
          'without ECH before giving up', () async {
        // Iran stopped answering ECH's public name on 2026-10-21; the same
        // credential through a clean address with another hello got through.
        late final FakeXrayTunnelController tunnel;
        final harness = _harness(
          tunnelCarries: (_) async =>
              !(tunnel.lastConnectConfig ?? '').contains('echConfigList'),
        );
        tunnel = harness.xrayTunnel;
        addTearDown(harness.container.dispose);
        final DevicesController notifier = await setUpXraySelection(harness);
        harness.repository.requestXrayClientResult = const XrayClientResult(
          clientId: 'client-1',
          uuid: '11111111-2222-3333-4444-555555555555',
          serverAddress: 'cdn.example.test',
          port: 443,
          sni: 'cdn.example.test',
          transport: 'websocket',
          transportSecurity: 'tls',
          adBlock: false,
          path: '/ws',
          echConfigList: 'cloudflare-ech.com+https://dns.example/dns-query',
        );

        await notifier.connect(_deviceId);

        final DevicesState state = harness.container.read(
          devicesControllerProvider,
        );
        expect(state.tunnelEstablished, isTrue);
        expect(harness.xrayTunnel.connectCalls, 2);
        expect(harness.xrayTunnel.lastConnectConfig, contains('http/1.1'));
        // The second dial: plain, no ECH, the WebSocket's own ALPN.
        expect(
          harness.xrayTunnel.lastConnectConfig,
          isNot(contains('echConfigList')),
        );
        expect(harness.xrayTunnel.lastConnectConfig, contains('"chrome"'));
      });

      test('a tunnel that answers too slowly is not Protected', () async {
        // Raw TCP+TLS to a throttled address: each small request took 5-7 s
        // and nothing larger got through, while the screen said Protected.
        int probes = 0;
        final harness = _harness(
          tunnelCarries: (_) async {
            if ((++probes).isOdd) {
              return true;
            }
            await Future<void>.delayed(const Duration(seconds: 5));
            return true;
          },
        );
        addTearDown(harness.container.dispose);
        final DevicesController notifier = await saved(harness);

        await notifier.connect(_deviceId);

        expect(
          harness.container.read(devicesControllerProvider).tunnelEstablished,
          isFalse,
        );
      });

      test('a CDN connection tells the address scan what to test', () async {
        // Learned only when that screen was opened while connected, a
        // connect-then-disconnect left it asking to connect once.
        final harness = _harness();
        addTearDown(harness.container.dispose);
        final DevicesController notifier = await saved(harness);

        await notifier.connect(_deviceId);
        await Future<void>.delayed(Duration.zero);

        expect(
          harness.container
              .read(advancedSettingsControllerProvider)
              .cleanIpHost,
          _xrayClientResult().serverAddress,
        );
      });

      test('the same credential again is not tried twice', () async {
        final harness = _harness(tunnelCarries: (_) async => false);
        addTearDown(harness.container.dispose);
        final DevicesController notifier = await saved(harness);

        await notifier.connect(_deviceId);

        expect(harness.xrayTunnel.connectCalls, 1);
        expect(
          harness.container.read(devicesControllerProvider).tunnelEstablished,
          isFalse,
        );
      });
    });

    test(
      'once the server answers again, a saved-credential connection is replaced',
      () async {
        // A tunnel raised with the phone offline did not recover when the
        // network came back (measured on a phone); one raised online did. So
        // the moment the server can be reached, the saved-credential connection
        // is swapped for one the server has just issued.
        final harness = _harness();
        addTearDown(harness.container.dispose);
        final DevicesController notifier = await setUpXraySelection(harness);
        // Saved by an earlier run whose tunnel ended without Disconnect -- a
        // drop, a reboot. Disconnect revokes, and so forgets it too.
        await harness.container
            .read(xrayCredentialStoreProvider)
            .write(
              serverCode: 'ams-2',
              profileCode: 'vless-xhttp-tls',
              credential: _xrayClientResult(),
            );
        harness.repository.requestXrayClientResult = _xrayClientResult();
        harness.repository.requestXrayClientError =
            const NebulaConnectivityException('connection refused');
        await notifier.connect(_deviceId);
        expect(
          harness.container.read(devicesControllerProvider).fromSavedCredential,
          isTrue,
        );
        final int callsBefore = harness.repository.requestXrayClientCalls;

        harness.repository.requestXrayClientError = null;
        await notifier.refreshAfterOffline(_deviceId);

        final DevicesState state = harness.container.read(
          devicesControllerProvider,
        );
        expect(harness.repository.requestXrayClientCalls, callsBefore + 1);
        expect(state.tunnelEstablished, isTrue);
        expect(state.fromSavedCredential, isFalse);
      },
    );

    test('a connection the server issued is left alone', () async {
      final harness = _harness();
      addTearDown(harness.container.dispose);
      final DevicesController notifier = await setUpXraySelection(harness);
      harness.repository.requestXrayClientResult = _xrayClientResult();
      await notifier.connect(_deviceId);
      final int callsBefore = harness.repository.requestXrayClientCalls;

      await notifier.refreshAfterOffline(_deviceId);

      expect(harness.repository.requestXrayClientCalls, callsBefore);
      expect(
        harness.container.read(devicesControllerProvider).tunnelEstablished,
        isTrue,
      );
    });

    test(
      'Disconnect keeps the credential, so an offline connect can use it',
      () async {
        final harness = _harness();
        addTearDown(harness.container.dispose);
        final DevicesController notifier = await setUpXraySelection(harness);
        harness.repository.requestXrayClientResult = _xrayClientResult();
        await notifier.connect(_deviceId);
        await notifier.disconnect(_deviceId);

        harness.repository.requestXrayClientError =
            const NebulaConnectivityException('connection refused');
        await notifier.connect(_deviceId);

        final DevicesState state = harness.container.read(
          devicesControllerProvider,
        );
        expect(state.tunnelEstablished, isTrue);
        expect(state.fromSavedCredential, isTrue);
      },
    );

    test(
      'with nothing saved, an unreachable server is still a failed connect',
      () async {
        final harness = _harness();
        addTearDown(harness.container.dispose);
        final DevicesController notifier = await setUpXraySelection(harness);
        harness.repository.requestXrayClientError =
            const NebulaConnectivityException('connection refused');

        await notifier.connect(_deviceId);

        final DevicesState state = harness.container.read(
          devicesControllerProvider,
        );
        expect(state.tunnelEstablished, isFalse);
        expect(state.fromSavedCredential, isFalse);
        expect(state.actionErrorMessage, isNotNull);
      },
    );

    test('the notification is titled with the server people chose', () async {
      final harness = _harness();
      addTearDown(harness.container.dispose);
      final DevicesController notifier = await setUpXraySelection(harness);
      harness.repository.requestXrayClientResult = _xrayClientResult();

      await notifier.connect(_deviceId);

      expect(harness.xrayTunnel.lastSessionName, 'Amsterdam 2');
      expect(harness.xrayTunnel.lastNotificationShowsSpeed, isTrue);
      expect(harness.xrayTunnel.lastDisconnectLabel, 'Disconnect');
    });

    test('turning the speed off reaches the notification', () async {
      final harness = _harness();
      addTearDown(harness.container.dispose);
      await harness.protection.write(
        ProtectionPreferences.defaults.copyWith(notificationSpeed: false),
      );
      final DevicesController notifier = await setUpXraySelection(harness);
      harness.repository.requestXrayClientResult = _xrayClientResult();

      await notifier.connect(_deviceId);

      expect(harness.xrayTunnel.lastNotificationShowsSpeed, isFalse);
    });

    test('requests an Xray client and brings up the tunnel', () async {
      final harness = _harness();
      addTearDown(harness.container.dispose);
      final DevicesController notifier = await setUpXraySelection(harness);
      harness.repository.requestXrayClientResult = _xrayClientResult();

      await notifier.connect(_deviceId);

      final DevicesState state = harness.container.read(
        devicesControllerProvider,
      );
      expect(harness.repository.requestXrayClientCalls, 1);
      expect(harness.repository.lastXrayRequestedServerCode, 'ams-2');
      expect(
        harness.repository.lastXrayRequestedProfileCode,
        'vless-xhttp-tls',
      );
      expect(state.isConnected, isTrue);
      expect(state.connectedServerCode, 'ams-2');
      expect(state.activeProtocolCode, 'vless');
      expect(state.activeProfileCode, 'vless-xhttp-tls');
      expect(state.tunnelEstablished, isTrue);
      expect(harness.xrayTunnel.requestPermissionCalls, 1);
      expect(harness.xrayTunnel.connectCalls, 1);
      expect(
        harness.xrayTunnel.lastConnectConfig,
        contains('ams-1.example.test'),
      );
      expect(harness.xrayTunnel.lastConnectConfig, contains('xhttp'));
      // The WireGuard path must not have been touched.
      expect(harness.tunnel.connectCalls, 0);
    });

    // Xray's tunnel is up once the engine starts, server or no server. With
    // saved credentials for a server that was gone, Windows said Protected
    // for a minute and a half while every lookup failed.
    test('takes an Xray tunnel down again when nothing gets through', () async {
      int probes = 0;
      final harness = _harness(
        tunnelCarries: (_) async {
          probes++;
          return false;
        },
      );
      addTearDown(harness.container.dispose);
      final DevicesController notifier = await setUpXraySelection(harness);
      harness.repository.requestXrayClientResult = _xrayClientResult();

      await notifier.connect(_deviceId);

      final DevicesState state = harness.container.read(
        devicesControllerProvider,
      );
      expect(probes, 3);
      expect(harness.xrayTunnel.connectCalls, 1);
      expect(harness.xrayTunnel.disconnectCalls, greaterThanOrEqualTo(1));
      expect(state.tunnelEstablished, isFalse);
      expect(state.isConnected, isFalse);
      expect(
        state.actionErrorMessage,
        harness.container.read(appTextProvider).errorTunnelNoTraffic,
      );
    });

    // In offline mode nothing else notices that the device itself is not
    // online, and "this network may be blocking the protocol" sends the
    // person to try other protocols that cannot help.
    test('says offline, not blocked, when the device is not online', () async {
      final harness = _harness(
        tunnelCarries: (_) async => false,
        online: () async => false,
      );
      addTearDown(harness.container.dispose);
      final DevicesController notifier = await setUpXraySelection(harness);
      harness.repository.requestXrayClientResult = _xrayClientResult();

      await notifier.connect(_deviceId);

      final DevicesState state = harness.container.read(
        devicesControllerProvider,
      );
      expect(state.tunnelEstablished, isFalse);
      expect(
        state.actionErrorMessage,
        harness.container.read(appTextProvider).errorOffline,
      );
    });

    test('off screen, a failed connect is not called offline', () async {
      // Android may hold back a backgrounded app's own requests; an online
      // phone was told it was offline (2026-10-29).
      final harness = _harness(
        tunnelCarries: (_) async => false,
        online: () async => false,
        trafficMeaningful: false,
      );
      addTearDown(harness.container.dispose);
      final DevicesController notifier = await setUpXraySelection(harness);
      harness.repository.requestXrayClientResult = _xrayClientResult();

      await notifier.connect(_deviceId);

      expect(
        harness.container.read(devicesControllerProvider).actionErrorMessage,
        harness.container.read(appTextProvider).errorTunnelNoTraffic,
      );
    });

    // Online, the step to the server that failed says more than "may be
    // blocking it": the name, the connection or the certificate.
    for (final (ServerReach, String Function(AppText)) c
        in <(ServerReach, String Function(AppText))>[
          (ServerReach.nameNotFound, (AppText t) => t.errorServerNameNotFound),
          (ServerReach.unreachable, (AppText t) => t.errorServerUnreachable),
          (
            ServerReach.certificateRejected,
            (AppText t) => t.errorServerCertificate,
          ),
          (ServerReach.reachable, (AppText t) => t.errorTunnelNoTraffic),
        ]) {
      test('says why nothing got through: ${c.$1.name}', () async {
        final harness = _harness(
          tunnelCarries: (_) async => false,
          reach: (XrayClientResult _) async => c.$1,
        );
        addTearDown(harness.container.dispose);
        final DevicesController notifier = await setUpXraySelection(harness);
        harness.repository.requestXrayClientResult = _xrayClientResult();

        await notifier.connect(_deviceId);

        expect(
          harness.container.read(devicesControllerProvider).actionErrorMessage,
          c.$2(harness.container.read(appTextProvider)),
        );
      });
    }

    group('Automatic', () {
      Future<DevicesController> setUpAutomatic(
        ({
          ProviderContainer container,
          FakeServerRepository repository,
          InMemoryWireGuardKeyStore keyStore,
          FakeTunnelController tunnel,
          FakeXrayTunnelController xrayTunnel,
          InMemorySelectionStore selections,
          InMemorySplitTunnelStore splitTunnel,
          InMemoryProtectionStore protection,
          InMemoryAdvancedSettingsStore advanced,
        })
        harness,
      ) async {
        harness.repository.servers = <AvailableServer>[_manyXrayServer];
        harness.repository.requestXrayClientResult = _xrayClientResult();
        await harness.container.read(devicesControllerProvider.notifier).load();
        final DevicesController notifier = harness.container.read(
          devicesControllerProvider.notifier,
        );
        notifier.selectServer('ams-5');
        return notifier;
      }

      test('is what choosing a server selects', () async {
        final harness = _harness();
        addTearDown(harness.container.dispose);
        await setUpAutomatic(harness);

        expect(
          harness.container.read(devicesControllerProvider).selectedProfileCode,
          automaticProfileCode,
        );
      });

      // The direct profiles pass a quick check but a browser's traffic over
      // them was cut on a home line in Iran; Automatic leaves them out.
      test('skips the direct, hand-picked-only profiles', () async {
        final harness = _harness(tunnelCarries: (_) async => true);
        addTearDown(harness.container.dispose);
        harness.repository.servers = <AvailableServer>[
          AvailableServer(
            code: 'ams-5',
            displayName: 'Amsterdam 5',
            publicHost: 'ams-5.example.test',
            profiles: <AvailableProfile>[
              for (final (String code, String protocol) in <(String, String)>[
                ('shadowsocks-2022', 'shadowsocks'),
                ('vless-enc', 'vless'),
                ('vmess-raw', 'vmess'),
                ('vless-xhttp-tls', 'vless'),
              ])
                AvailableProfile(
                  code: code,
                  displayName: code,
                  protocolId: 'protocol-$protocol',
                  protocolCode: protocol,
                  adBlock: false,
                ),
            ],
          ),
        ];
        harness.repository.requestXrayClientResult = _xrayClientResult();
        await harness.container.read(devicesControllerProvider.notifier).load();
        final DevicesController notifier = harness.container.read(
          devicesControllerProvider.notifier,
        );
        notifier.selectServer('ams-5');

        await notifier.connect(_deviceId);

        final DevicesState state = harness.container.read(
          devicesControllerProvider,
        );
        expect(harness.xrayTunnel.connectCalls, 1);
        expect(state.activeProfileCode, 'vless-xhttp-tls');
      });

      // One protocol carrying nothing is no reason to give up: blocked on
      // this network, the next one may not be.
      test('moves to the next protocol when one carries nothing', () async {
        int probes = 0;
        // Three tries per protocol: the first one fails all three.
        final harness = _harness(tunnelCarries: (_) async => ++probes > 3);
        addTearDown(harness.container.dispose);
        final DevicesController notifier = await setUpAutomatic(harness);

        await notifier.connect(_deviceId);

        final DevicesState state = harness.container.read(
          devicesControllerProvider,
        );
        expect(harness.xrayTunnel.connectCalls, 2);
        expect(state.tunnelEstablished, isTrue);
        expect(state.activeProfileCode, 'vless-b-tls');
        expect(state.actionErrorMessage, isNull);
        // Still Automatic: the next connect chooses again.
        expect(state.selectedProfileCode, automaticProfileCode);
      });

      test('tries an inbound once, not again as its ad-block twin', () async {
        // Four tries: with twins counted apart, two went to one stalled
        // inbound and the one that worked was never reached.
        String? asked;
        final harness = _harness(
          tunnelCarries: (_) async => asked == 'vless-tcp-tls',
        );
        addTearDown(harness.container.dispose);
        harness.repository.servers = <AvailableServer>[
          AvailableServer(
            code: 'ams-5',
            displayName: 'Amsterdam 5',
            publicHost: 'ams-5.example.test',
            profiles: <AvailableProfile>[
              for (final String code in <String>[
                'vless-xhttp-tls',
                'vless-xhttp-tls-adblock',
                'vless-grpc-tls',
                'vless-grpc-tls-adblock',
                'vless-ws-tls',
                'vless-ws-tls-adblock',
                'vless-tcp-tls',
              ])
                AvailableProfile(
                  code: code,
                  displayName: code,
                  protocolId: 'protocol-vless',
                  protocolCode: 'vless',
                  adBlock: code.endsWith('-adblock'),
                ),
            ],
          ),
        ];
        harness.repository.requestXrayClientResult = _xrayClientResult();
        harness.repository.requestXrayClientResultFor = (String profile) {
          asked = profile;
          return null;
        };
        await harness.container.read(devicesControllerProvider.notifier).load();
        final DevicesController notifier = harness.container.read(
          devicesControllerProvider.notifier,
        );
        notifier.selectServer('ams-5');

        await notifier.connect(_deviceId);

        final DevicesState state = harness.container.read(
          devicesControllerProvider,
        );
        expect(state.tunnelEstablished, isTrue);
        expect(state.activeProfileCode, 'vless-tcp-tls');
      });

      test('passes over a protocol that just failed here', () async {
        // Its record says it failed minutes ago; trying it first again would
        // spend twenty seconds on what this network is blocking right now.
        final harness = _harness(tunnelCarries: (_) async => true);
        addTearDown(harness.container.dispose);
        final DevicesController notifier = await setUpAutomatic(harness);
        await harness.container
            .read(protocolHistoryStoreProvider)
            .record('ams-5', 'vless-a-tls', ProtocolOutcome.failure);

        await notifier.connect(_deviceId);

        final DevicesState state = harness.container.read(
          devicesControllerProvider,
        );
        expect(harness.xrayTunnel.connectCalls, 1);
        expect(state.activeProfileCode, 'vless-b-tls');
      });

      test('records what each protocol did', () async {
        int probes = 0;
        final harness = _harness(tunnelCarries: (_) async => ++probes > 3);
        addTearDown(harness.container.dispose);
        final DevicesController notifier = await setUpAutomatic(harness);

        await notifier.connect(_deviceId);

        final Map<String, ProtocolHistory> history = harness.container
            .read(protocolHistoryStoreProvider)
            .forServer('ams-5');
        expect(history['vless-a-tls']?.failures, 1);
        expect(history['vless-b-tls']?.successes, 1);
      });

      test('gives up after four, and says none got through', () async {
        final harness = _harness(tunnelCarries: (_) async => false);
        addTearDown(harness.container.dispose);
        final DevicesController notifier = await setUpAutomatic(harness);

        await notifier.connect(_deviceId);

        final DevicesState state = harness.container.read(
          devicesControllerProvider,
        );
        expect(harness.xrayTunnel.connectCalls, 4);
        expect(state.tunnelEstablished, isFalse);
        expect(
          state.actionErrorMessage,
          harness.container.read(appTextProvider).errorNoProtocolWorked,
        );
      });

      test('stops at once when the device is not online', () async {
        final harness = _harness(
          tunnelCarries: (_) async => false,
          online: () async => false,
        );
        addTearDown(harness.container.dispose);
        final DevicesController notifier = await setUpAutomatic(harness);

        await notifier.connect(_deviceId);

        final DevicesState state = harness.container.read(
          devicesControllerProvider,
        );
        expect(harness.xrayTunnel.connectCalls, 1);
        expect(
          state.actionErrorMessage,
          harness.container.read(appTextProvider).errorOffline,
        );
      });

      // No other protocol changes an allowance that is used up.
      test('stops at once when the allowance is used up', () async {
        final harness = _harness();
        addTearDown(harness.container.dispose);
        final DevicesController notifier = await setUpAutomatic(harness);
        harness.repository.requestXrayClientError = const NebulaApiException(
          statusCode: 402,
          detail: 'quota',
        );

        await notifier.connect(_deviceId);

        expect(harness.repository.requestXrayClientCalls, 1);
        expect(
          harness.container.read(devicesControllerProvider).actionErrorMessage,
          harness.container.read(appTextProvider).errorQuotaExhausted,
        );
      });
      // The person said no; asking again for the next protocol, then blaming
      // the network, was what a first install showed.
      test('stops at once when VPN permission is refused', () async {
        final harness = _harness();
        addTearDown(harness.container.dispose);
        final DevicesController notifier = await setUpAutomatic(harness);
        harness.xrayTunnel.permissionGranted = false;

        await notifier.connect(_deviceId);

        expect(harness.xrayTunnel.requestPermissionCalls, 1);
        expect(
          harness.container.read(devicesControllerProvider).actionErrorMessage,
          harness.container.read(appTextProvider).vpnPermissionNotGranted,
        );
      });
    });

    test('a link connects with no server at all', () async {
      final harness = _harness(
        freeMode: true,
        servers: LocalServerRepository(
          builtIn: const <String>[
            'vless://0f1e2d3c-4b5a-4978-8a6b-5c4d3e2f1a0b@188.114.97.6:443'
                '?security=tls&type=ws&sni=relay.example.workers.dev#Relay',
          ],
          store: InMemoryFreeLinkStore(),
        ),
      );
      addTearDown(harness.container.dispose);
      final DevicesController notifier = harness.container.read(
        devicesControllerProvider.notifier,
      );
      await notifier.load();
      final AvailableServer relay = harness.container
          .read(devicesControllerProvider)
          .servers
          .single;
      // Chosen without being asked: there is nothing to weigh it against.
      expect(
        harness.container.read(devicesControllerProvider).selectedServerCode,
        relay.code,
      );

      await notifier.connect(freeDeviceId);

      DevicesState state = harness.container.read(devicesControllerProvider);
      expect(state.tunnelEstablished, isTrue);
      expect(state.actionErrorMessage, isNull);
      expect(state.xrayClient!.sni, 'relay.example.workers.dev');
      expect(harness.xrayTunnel.connectCalls, 1);
      // The server this build may also know of was never asked for anything.
      expect(harness.repository.requestXrayClientCalls, 0);

      await notifier.disconnect(freeDeviceId);

      state = harness.container.read(devicesControllerProvider);
      expect(state.tunnelEstablished, isFalse);
      expect(state.isConnected, isFalse);
      expect(state.actionErrorMessage, isNull);
    });

    // A throttled address answers the first request and stalls the rest.
    test('one answer then silence is no tunnel', () async {
      int probes = 0;
      final harness = _harness(tunnelCarries: (_) async => ++probes == 1);
      addTearDown(harness.container.dispose);
      final DevicesController notifier = await setUpXraySelection(harness);
      harness.repository.requestXrayClientResult = _xrayClientResult();

      await notifier.connect(_deviceId);

      expect(probes, 2);
      expect(
        harness.container.read(devicesControllerProvider).tunnelEstablished,
        isFalse,
      );
    });

    test('a tunnel that carries nothing is asked for again over the next '
        'route', () async {
      int moves = 0;
      final harness = _harness(
        // The first tunnel carries nothing; the one through the next route
        // does.
        tunnelCarries: (_) async => moves > 0,
        moveRoute: () => ++moves == 1,
      );
      addTearDown(harness.container.dispose);
      final DevicesController notifier = await setUpXraySelection(harness);
      harness.repository.requestXrayClientResult = _xrayClientResult();

      await notifier.connect(_deviceId);

      expect(moves, 1);
      expect(harness.xrayTunnel.connectCalls, 2);
      expect(
        harness.container.read(devicesControllerProvider).tunnelEstablished,
        isTrue,
      );
    });

    test('keeps an Xray tunnel whose second try gets through', () async {
      int probes = 0;
      final harness = _harness(tunnelCarries: (_) async => ++probes >= 2);
      addTearDown(harness.container.dispose);
      final DevicesController notifier = await setUpXraySelection(harness);
      harness.repository.requestXrayClientResult = _xrayClientResult();

      await notifier.connect(_deviceId);

      // The answer, and one more after it.
      expect(probes, 3);
      expect(
        harness.container.read(devicesControllerProvider).tunnelEstablished,
        isTrue,
      );
    });

    test(
      'routes a non-vless, non-wireguard protocol (Hysteria2) through the Xray path too',
      () async {
        final harness = _harness();
        addTearDown(harness.container.dispose);
        harness.repository.servers = <AvailableServer>[_hysteriaOnlyServer];
        await harness.container.read(devicesControllerProvider.notifier).load();
        final DevicesController notifier = harness.container.read(
          devicesControllerProvider.notifier,
        );
        notifier.selectServer('ams-3');
        notifier.selectProfile('hysteria2');
        harness.repository.requestXrayClientResult = _hysteriaClientResult();

        await notifier.connect(_deviceId);

        final DevicesState state = harness.container.read(
          devicesControllerProvider,
        );
        expect(harness.repository.requestXrayClientCalls, 1);
        expect(harness.repository.lastXrayRequestedProfileCode, 'hysteria2');
        expect(state.activeProtocolCode, 'hysteria2');
        expect(state.activeProfileCode, 'hysteria2');
        expect(state.tunnelEstablished, isTrue);
        expect(harness.tunnel.connectCalls, 0);
      },
    );

    test(
      'records the client but not a tunnel when VPN permission is denied',
      () async {
        final harness = _harness();
        addTearDown(harness.container.dispose);
        final DevicesController notifier = await setUpXraySelection(harness);
        harness.repository.requestXrayClientResult = _xrayClientResult();
        harness.xrayTunnel.permissionGranted = false;

        await notifier.connect(_deviceId);

        final DevicesState state = harness.container.read(
          devicesControllerProvider,
        );
        expect(state.isConnected, isTrue);
        expect(state.tunnelEstablished, isFalse);
        expect(state.actionErrorMessage, 'VPN permission was not granted.');
        expect(harness.xrayTunnel.connectCalls, 0);
      },
    );

    test(
      'records the client but not a tunnel when the platform tunnel fails to start',
      () async {
        final harness = _harness();
        addTearDown(harness.container.dispose);
        final DevicesController notifier = await setUpXraySelection(harness);
        harness.repository.requestXrayClientResult = _xrayClientResult();
        harness.xrayTunnel.connectError = StateError('v2ray start failed');

        await notifier.connect(_deviceId);

        final DevicesState state = harness.container.read(
          devicesControllerProvider,
        );
        expect(state.isConnected, isTrue);
        expect(state.tunnelEstablished, isFalse);
        expect(state.actionErrorMessage, isNotNull);
      },
    );

    test(
      'a failed request surfaces an error and leaves the client unset',
      () async {
        final harness = _harness();
        addTearDown(harness.container.dispose);
        final DevicesController notifier = await setUpXraySelection(harness);
        harness.repository.requestXrayClientError = const NebulaApiException(
          statusCode: 409,
          detail: 'Device already has an Xray client',
        );

        await notifier.connect(_deviceId);

        final DevicesState state = harness.container.read(
          devicesControllerProvider,
        );
        expect(state.isConnected, isFalse);
        expect(state.actionErrorMessage, 'Device already has an Xray client');
      },
    );
  });

  group('DevicesController.disconnect', () {
    test(
      'clears the peer and calls revoke with the connected server code',
      () async {
        final harness = _harness();
        addTearDown(harness.container.dispose);
        harness.repository.servers = <AvailableServer>[_wireGuardOnlyServer];
        await harness.container.read(devicesControllerProvider.notifier).load();
        final DevicesController notifier = harness.container.read(
          devicesControllerProvider.notifier,
        );
        notifier.selectServer('ams-1');
        notifier.selectProfile('wg-default');
        harness.repository.requestPeerResult = _peerResult();
        await notifier.connect(_deviceId);

        await notifier.disconnect(_deviceId);

        final DevicesState state = harness.container.read(
          devicesControllerProvider,
        );
        expect(state.isConnected, isFalse);
        expect(state.tunnelEstablished, isFalse);
        expect(harness.repository.revokePeerCalls, 1);
        expect(harness.repository.lastRevokedServerCode, 'ams-1');
        // The local tunnel must be torn down before the server-side peer is
        // revoked, not left running against a now-revoked peer.
        expect(harness.tunnel.disconnectCalls, 1);
        expect(harness.xrayTunnel.disconnectCalls, 0);
      },
    );

    test(
      'skips tearing down the tunnel if none was ever established',
      () async {
        final harness = _harness();
        addTearDown(harness.container.dispose);
        harness.repository.servers = <AvailableServer>[_wireGuardOnlyServer];
        await harness.container.read(devicesControllerProvider.notifier).load();
        final DevicesController notifier = harness.container.read(
          devicesControllerProvider.notifier,
        );
        notifier.selectServer('ams-1');
        notifier.selectProfile('wg-default');
        harness.repository.requestPeerResult = _peerResult();
        harness.tunnel.permissionGranted = false;
        await notifier.connect(_deviceId);

        await notifier.disconnect(_deviceId);

        expect(harness.tunnel.disconnectCalls, 0);
        expect(harness.repository.revokePeerCalls, 1);
      },
    );

    test('does nothing when there is no connected server', () async {
      final harness = _harness();
      addTearDown(harness.container.dispose);
      final DevicesController notifier = harness.container.read(
        devicesControllerProvider.notifier,
      );

      await notifier.disconnect(_deviceId);

      expect(harness.repository.revokePeerCalls, 0);
    });

    test('tears down the Xray tunnel and keeps the credential', () async {
      final harness = _harness();
      addTearDown(harness.container.dispose);
      harness.repository.servers = <AvailableServer>[_xrayOnlyServer];
      await harness.container.read(devicesControllerProvider.notifier).load();
      final DevicesController notifier = harness.container.read(
        devicesControllerProvider.notifier,
      );
      notifier.selectServer('ams-2');
      notifier.selectProfile('vless-xhttp-tls');
      harness.repository.requestXrayClientResult = _xrayClientResult();
      await notifier.connect(_deviceId);

      await notifier.disconnect(_deviceId);

      final DevicesState state = harness.container.read(
        devicesControllerProvider,
      );
      expect(state.isConnected, isFalse);
      expect(state.tunnelEstablished, isFalse);
      expect(harness.repository.revokeXrayClientCalls, 0);
      expect(harness.xrayTunnel.disconnectCalls, 1);
      expect(harness.tunnel.disconnectCalls, 0);
      expect(harness.repository.revokePeerCalls, 0);
    });
  });
}

/// Remembering the last choice across launches.
///
/// A remembered choice is a hint, not an instruction: what an account can
/// reach changes between launches, and restoring something withdrawn would
/// fail at connect time with nothing on screen explaining why.
void _selectionMemoryTests() {
  test('the last choice is put back on the next launch', () async {
    final InMemorySelectionStore remembered = InMemorySelectionStore();
    final first = _harness(selections: remembered);
    addTearDown(first.container.dispose);
    first.repository.servers = <AvailableServer>[_wireGuardOnlyServer];
    final DevicesController opening = first.container.read(
      devicesControllerProvider.notifier,
    );
    await opening.load();
    opening.selectServer('ams-1');
    opening.selectProfile('wg-default');

    // A second launch, sharing only what was written to storage.
    final second = _harness(selections: remembered);
    addTearDown(second.container.dispose);
    second.repository.servers = <AvailableServer>[_wireGuardOnlyServer];
    await second.container.read(devicesControllerProvider.notifier).load();

    final DevicesState state = second.container.read(devicesControllerProvider);
    expect(state.selectedServerCode, 'ams-1');
    expect(state.selectedProfileCode, 'wg-default');
  });

  test(
    'a link chosen before links were grouped is found in its group',
    () async {
      // Free mode used to list a server per link, so the saved server is a
      // link's own code. After the update the link is a choice in a group;
      // nobody should have to pick it again.
      final InMemorySelectionStore remembered = InMemorySelectionStore()
        ..writeServerCode('free-0000abcd')
        ..writeProfileCode('vless-ws-tls');
      final harness = _harness(selections: remembered);
      addTearDown(harness.container.dispose);
      harness.repository.servers = <AvailableServer>[
        const AvailableServer(
          code: 'free-sub-12345678',
          displayName: 'relay.example.org',
          publicHost: '',
          profiles: <AvailableProfile>[
            AvailableProfile(
              code: 'free-0000abcd',
              displayName: 'WS-CF-auto',
              protocolId: 'free-0000abcd',
              protocolCode: 'vless',
              adBlock: false,
            ),
          ],
        ),
      ];

      await harness.container.read(devicesControllerProvider.notifier).load();

      final DevicesState state = harness.container.read(
        devicesControllerProvider,
      );
      expect(state.selectedServerCode, 'free-sub-12345678');
      expect(state.selectedProfileCode, 'free-0000abcd');
      expect(state.profileLabel('free-0000abcd'), 'WS-CF-auto');
    },
  );

  test('a link chosen in a subscription under its old code is found', () async {
    // 0.1.24 named a subscription's group after its host; the code now comes
    // from its address. The link chosen in it leads back to the group.
    final InMemorySelectionStore remembered = InMemorySelectionStore()
      ..writeServerCode('free-sub-0ld0c0de')
      ..writeProfileCode('free-0000abcd');
    final harness = _harness(selections: remembered);
    addTearDown(harness.container.dispose);
    harness.repository.servers = <AvailableServer>[
      const AvailableServer(
        code: 'free-sub-12345678',
        displayName: 'WhiteDNS',
        publicHost: '',
        profiles: <AvailableProfile>[
          AvailableProfile(
            code: 'free-0000abcd',
            displayName: 'US552',
            protocolId: 'free-0000abcd',
            protocolCode: 'vless',
            adBlock: false,
          ),
        ],
      ),
    ];

    await harness.container.read(devicesControllerProvider.notifier).load();

    final DevicesState state = harness.container.read(
      devicesControllerProvider,
    );
    expect(state.selectedServerCode, 'free-sub-12345678');
    expect(state.selectedProfileCode, 'free-0000abcd');
  });

  test('a server the account can no longer reach is not restored', () async {
    final InMemorySelectionStore remembered = InMemorySelectionStore()
      ..writeServerCode('ams-9')
      ..writeProfileCode('wg-default');
    final harness = _harness(selections: remembered);
    addTearDown(harness.container.dispose);
    harness.repository.servers = <AvailableServer>[_wireGuardOnlyServer];

    await harness.container.read(devicesControllerProvider.notifier).load();

    final DevicesState state = harness.container.read(
      devicesControllerProvider,
    );
    // Not the withdrawn one; the one server left is chosen instead, so the
    // person is not asked to pick between one option.
    expect(state.selectedServerCode, 'ams-1');
    expect(state.selectedProfileCode, automaticProfileCode);
  });

  test(
    'a profile the server no longer offers leaves the server chosen',
    () async {
      // Half a remembered choice is still worth restoring: the server is still
      // reachable, and only the protocol has to be picked again.
      final InMemorySelectionStore remembered = InMemorySelectionStore()
        ..writeServerCode('ams-1')
        ..writeProfileCode('vless-retired-tls');
      final harness = _harness(selections: remembered);
      addTearDown(harness.container.dispose);
      harness.repository.servers = <AvailableServer>[_wireGuardOnlyServer];

      await harness.container.read(devicesControllerProvider.notifier).load();

      final DevicesState state = harness.container.read(
        devicesControllerProvider,
      );
      expect(state.selectedServerCode, 'ams-1');
      expect(state.selectedProfileCode, automaticProfileCode);
    },
  );

  test(
    'changing server forgets the profile that belonged to the old one',
    () async {
      final InMemorySelectionStore remembered = InMemorySelectionStore();
      final harness = _harness(selections: remembered);
      addTearDown(harness.container.dispose);
      harness.repository.servers = <AvailableServer>[
        _wireGuardOnlyServer,
        _xrayOnlyServer,
      ];
      final DevicesController notifier = harness.container.read(
        devicesControllerProvider.notifier,
      );
      await notifier.load();

      notifier.selectServer('ams-1');
      notifier.selectProfile('wg-default');
      notifier.selectServer('ams-2');

      expect(remembered.readServerCode(), 'ams-2');
      expect(remembered.readProfileCode(), automaticProfileCode);
    },
  );

  test(
    'a choice made this run is not overwritten by the remembered one',
    () async {
      final InMemorySelectionStore remembered = InMemorySelectionStore()
        ..writeServerCode('ams-2');
      final harness = _harness(selections: remembered);
      addTearDown(harness.container.dispose);
      harness.repository.servers = <AvailableServer>[
        _wireGuardOnlyServer,
        _xrayOnlyServer,
      ];
      final DevicesController notifier = harness.container.read(
        devicesControllerProvider.notifier,
      );

      notifier.selectServer('ams-1');
      await notifier.load();

      expect(
        harness.container.read(devicesControllerProvider).selectedServerCode,
        'ams-1',
      );
    },
  );

  group('DevicesController.connect (split tunnelling)', () {
    test('the chosen apps reach the WireGuard tunnel', () async {
      // The whole feature is only real at this boundary. A selection the
      // picker stores but never hands to the backend leaves somebody
      // believing an app is outside the tunnel while its traffic is not.
      final harness = _harness();
      addTearDown(harness.container.dispose);
      await harness.splitTunnel.writeExcludedPackages(<String>{
        'com.bank.app',
        'com.maps.app',
      });
      harness.repository.servers = <AvailableServer>[_wireGuardOnlyServer];
      await harness.container.read(devicesControllerProvider.notifier).load();
      final DevicesController notifier = harness.container.read(
        devicesControllerProvider.notifier,
      );
      notifier.selectServer('ams-1');
      notifier.selectProfile('wg-default');
      harness.repository.requestPeerResult = _peerResult();

      await notifier.connect(_deviceId);

      expect(harness.tunnel.lastExcludedPackages, <String>[
        'com.bank.app',
        'com.maps.app',
      ]);
    });

    test('the chosen apps reach the Xray tunnel', () async {
      final harness = _harness();
      addTearDown(harness.container.dispose);
      await harness.splitTunnel.writeExcludedPackages(<String>{'com.bank.app'});
      harness.repository.servers = <AvailableServer>[_xrayOnlyServer];
      await harness.container.read(devicesControllerProvider.notifier).load();
      final DevicesController notifier = harness.container.read(
        devicesControllerProvider.notifier,
      );
      notifier.selectServer('ams-2');
      notifier.selectProfile('vless-xhttp-tls');
      harness.repository.requestXrayClientResult = _xrayClientResult();

      await notifier.connect(_deviceId);

      expect(harness.xrayTunnel.lastExcludedPackages, <String>['com.bank.app']);
    });

    test('a routing change while connected reconnects to apply it', () async {
      // Changing "sanctioned services only" used to wait for the next
      // connection, which on the phone looked like the switch doing nothing.
      final harness = _harness();
      addTearDown(harness.container.dispose);
      harness.repository.servers = <AvailableServer>[_xrayOnlyServer];
      await harness.container.read(devicesControllerProvider.notifier).load();
      final DevicesController notifier = harness.container.read(
        devicesControllerProvider.notifier,
      );
      notifier.selectServer('ams-2');
      notifier.selectProfile('vless-xhttp-tls');
      harness.repository.requestXrayClientResult = _xrayClientResult();
      await notifier.connect(_deviceId);
      final AdvancedSettingsController settings = harness.container.read(
        advancedSettingsControllerProvider.notifier,
      );

      // Not routing: the running connection is left alone.
      await settings.setMuxEnabled(enabled: true);
      await Future<void>.delayed(const Duration(milliseconds: 800));
      expect(harness.xrayTunnel.connectCalls, 1);

      await settings.setRoutingMode(RoutingMode.sanctionedOnly);
      for (int i = 0; i < 40 && harness.xrayTunnel.connectCalls < 2; i++) {
        await Future<void>.delayed(const Duration(milliseconds: 100));
      }

      expect(harness.xrayTunnel.connectCalls, 2);
      expect(harness.xrayTunnel.lastConnectConfig, contains('openai.com'));
      final DevicesState state = harness.container.read(
        devicesControllerProvider,
      );
      expect(state.isConnected, isTrue);
      expect(state.sanctionsOnly, isTrue);
    });

    test('nothing excluded hands the backend an empty list', () async {
      // Not null and not a placeholder: the default has to mean "everything
      // goes through the tunnel", which is what an empty list says.
      final harness = _harness();
      addTearDown(harness.container.dispose);
      harness.repository.servers = <AvailableServer>[_wireGuardOnlyServer];
      await harness.container.read(devicesControllerProvider.notifier).load();
      final DevicesController notifier = harness.container.read(
        devicesControllerProvider.notifier,
      );
      notifier.selectServer('ams-1');
      notifier.selectProfile('wg-default');
      harness.repository.requestPeerResult = _peerResult();

      await notifier.connect(_deviceId);

      expect(harness.tunnel.lastExcludedPackages, isEmpty);
    });
  });

  group('DevicesController.connect (local network)', () {
    test('the default claims everything', () async {
      // Off by default. The private ranges are almost always a machine in the
      // same room, but "almost always" is not the default to pick for
      // somebody whose threat model is their network operator.
      final harness = _harness();
      addTearDown(harness.container.dispose);
      harness.repository.servers = <AvailableServer>[_xrayOnlyServer];
      await harness.container.read(devicesControllerProvider.notifier).load();
      final DevicesController notifier = harness.container.read(
        devicesControllerProvider.notifier,
      );
      notifier.selectServer('ams-2');
      notifier.selectProfile('vless-xhttp-tls');
      harness.repository.requestXrayClientResult = _xrayClientResult();

      await notifier.connect(_deviceId);

      expect(harness.xrayTunnel.lastRoutes, <String>['0.0.0.0/0', '::/0']);
    });

    test(
      'turning it on stops the Xray tunnel claiming the private ranges',
      () async {
        final harness = _harness();
        addTearDown(harness.container.dispose);
        await harness.protection.write(
          ProtectionPreferences.defaults.copyWith(bypassLocalNetwork: true),
        );
        harness.repository.servers = <AvailableServer>[_xrayOnlyServer];
        await harness.container.read(devicesControllerProvider.notifier).load();
        final DevicesController notifier = harness.container.read(
          devicesControllerProvider.notifier,
        );
        notifier.selectServer('ams-2');
        notifier.selectProfile('vless-xhttp-tls');
        harness.repository.requestXrayClientResult = _xrayClientResult();

        await notifier.connect(_deviceId);

        final List<String> routes = harness.xrayTunnel.lastRoutes!;
        expect(routes, isNot(contains('0.0.0.0/0')));
        expect(routes, isNot(contains('192.168.0.0/16')));
        // Still claimed, so IPv6 cannot leak around the tunnel.
        expect(routes, contains('::/0'));
        // And the public internet is still taken.
        expect(routes, contains('8.0.0.0/7'));
      },
    );

    test('turning it on narrows the WireGuard AllowedIPs', () async {
      final harness = _harness();
      addTearDown(harness.container.dispose);
      await harness.protection.write(
        ProtectionPreferences.defaults.copyWith(bypassLocalNetwork: true),
      );
      harness.repository.servers = <AvailableServer>[_wireGuardOnlyServer];
      await harness.container.read(devicesControllerProvider.notifier).load();
      final DevicesController notifier = harness.container.read(
        devicesControllerProvider.notifier,
      );
      notifier.selectServer('ams-1');
      notifier.selectProfile('wg-default');
      harness.repository.requestPeerResult = _peerResult();

      await notifier.connect(_deviceId);

      final String config = harness.tunnel.lastConnectConfig!;
      expect(config, isNot(contains('AllowedIPs = 0.0.0.0/0')));
      // Starts at 1.0.0.0/8 because 0.0.0.0/8 is excluded too.
      expect(config, contains('AllowedIPs = 1.0.0.0/8,'));
      expect(config, contains('8.0.0.0/7'));
      expect(config, isNot(contains('192.168.0.0/16')));
      // The server also asked for ::/0, and that entry is passed through
      // untouched -- narrowing is an IPv4 operation here.
      expect(config, contains('::/0'));
    });

    test(
      'the kill switch setting reaches the tunnel, off by default',
      () async {
        final harness = _harness();
        addTearDown(harness.container.dispose);
        harness.repository.servers = <AvailableServer>[_wireGuardOnlyServer];
        await harness.container.read(devicesControllerProvider.notifier).load();
        final DevicesController notifier = harness.container.read(
          devicesControllerProvider.notifier,
        );
        notifier.selectServer('ams-1');
        notifier.selectProfile('wg-default');
        harness.repository.requestPeerResult = _peerResult();

        await notifier.connect(_deviceId);
        expect(harness.tunnel.lastKillSwitch, isFalse);
        await notifier.disconnect(_deviceId);

        await harness.container
            .read(protectionControllerProvider.notifier)
            .setBlockWhenVpnDrops(enabled: true);
        await notifier.connect(_deviceId);
        expect(harness.tunnel.lastKillSwitch, isTrue);
      },
    );
  });
}

/// "Connect on launch": the switch was saved and shown for a long time
/// before anything read it.
void _connectOnLaunchTests() {
  /// A server and profile chosen on an earlier run.
  InMemorySelectionStore rememberedWireGuard() => InMemorySelectionStore()
    ..writeServerCode('ams-1')
    ..writeProfileCode('wg-default');

  /// The server list arriving on launch, before anything else happens.
  Future<DevicesController> loaded(
    ProviderContainer container,
    FakeServerRepository repository,
  ) async {
    repository.servers = <AvailableServer>[_wireGuardOnlyServer];
    repository.requestPeerResult = _peerResult();
    final DevicesController notifier = container.read(
      devicesControllerProvider.notifier,
    );
    await notifier.load();
    return notifier;
  }

  test('connects to the last used server', () async {
    final harness = _harness(selections: rememberedWireGuard());
    addTearDown(harness.container.dispose);
    final DevicesController notifier = await loaded(
      harness.container,
      harness.repository,
    );

    await notifier.connectOnLaunchIfWanted(_deviceId);

    final DevicesState state = harness.container.read(
      devicesControllerProvider,
    );
    expect(state.tunnelEstablished, isTrue);
    expect(state.connectedServerCode, 'ams-1');
    expect(harness.tunnel.connectCalls, 1);
  });

  test('a protocol that failed last time is not tried again unasked', () async {
    // A dead server held every launch at Connecting for over a minute.
    final harness = _harness(selections: rememberedWireGuard());
    addTearDown(harness.container.dispose);
    final DevicesController notifier = await loaded(
      harness.container,
      harness.repository,
    );
    await harness.container
        .read(protocolHistoryStoreProvider)
        .record('ams-1', 'wg-default', ProtocolOutcome.failure);

    await notifier.connectOnLaunchIfWanted(_deviceId);

    expect(harness.tunnel.connectCalls, 0);
  });

  test('a relay chosen for the person is not connected to unasked', () async {
    // Entering the free mode picks the first relay so the screen does not
    // say "Choose"; that is not somebody choosing to connect.
    final harness = _harness(
      freeMode: true,
      servers: LocalServerRepository(
        builtIn: const <String>[
          'vless://0f1e2d3c-4b5a-4978-8a6b-5c4d3e2f1a0b@188.114.97.6:443'
              '?security=tls&type=ws&sni=relay.example.workers.dev#Relay',
        ],
        store: InMemoryFreeLinkStore(),
      ),
    );
    addTearDown(harness.container.dispose);
    final DevicesController notifier = harness.container.read(
      devicesControllerProvider.notifier,
    );
    await notifier.load();

    await notifier.connectOnLaunchIfWanted(freeDeviceId);

    final DevicesState state = harness.container.read(
      devicesControllerProvider,
    );
    expect(state.selectedServerCode, isNotNull);
    expect(state.tunnelEstablished, isFalse);
    expect(harness.xrayTunnel.connectCalls, 0);
  });

  test('does nothing when the setting is off', () async {
    final harness = _harness(selections: rememberedWireGuard());
    addTearDown(harness.container.dispose);
    final DevicesController notifier = await loaded(
      harness.container,
      harness.repository,
    );
    await harness.protection.write(
      ProtectionPreferences.defaults.copyWith(connectOnLaunch: false),
    );

    await notifier.connectOnLaunchIfWanted(_deviceId);

    expect(harness.repository.requestPeerCalls, 0);
    expect(harness.tunnel.connectCalls, 0);
  });

  test('a first launch connects to nothing nobody chose', () async {
    final harness = _harness();
    addTearDown(harness.container.dispose);
    final DevicesController notifier = await loaded(
      harness.container,
      harness.repository,
    );

    await notifier.connectOnLaunchIfWanted(_deviceId);

    expect(harness.repository.requestPeerCalls, 0);
    expect(harness.tunnel.connectCalls, 0);
  });

  test('leaves a VPN that is already up alone', () async {
    // The tunnel can outlive the app. Connecting again would tear down a
    // working connection just because the app was opened.
    final harness = _harness(selections: rememberedWireGuard());
    addTearDown(harness.container.dispose);
    final DevicesController notifier = await loaded(
      harness.container,
      harness.repository,
    );
    harness.tunnel.vpnOwner = VpnOwner.own;

    await notifier.connectOnLaunchIfWanted(_deviceId);

    expect(harness.repository.requestPeerCalls, 0);
    expect(harness.tunnel.connectCalls, 0);
  });

  test('never raises the consent dialog on its own', () async {
    // Setting up another VPN app takes consent away from this one. Asking
    // again the moment the app opens would be a system dialog out of nowhere.
    final harness = _harness(selections: rememberedWireGuard());
    addTearDown(harness.container.dispose);
    final DevicesController notifier = await loaded(
      harness.container,
      harness.repository,
    );
    harness.tunnel.permissionHeld = false;

    await notifier.connectOnLaunchIfWanted(_deviceId);

    expect(harness.tunnel.requestPermissionCalls, 0);
    expect(harness.repository.requestPeerCalls, 0);
  });

  test('does nothing when the server list did not load', () async {
    final harness = _harness(selections: rememberedWireGuard());
    addTearDown(harness.container.dispose);
    final DevicesController notifier = await loaded(
      harness.container,
      harness.repository,
    );
    harness.repository.listError = const NebulaApiException(
      statusCode: 503,
      detail: 'Service unavailable',
    );
    await notifier.load();

    await notifier.connectOnLaunchIfWanted(_deviceId);

    expect(harness.tunnel.connectCalls, 0);
  });

  test('does nothing without a device', () async {
    final harness = _harness(selections: rememberedWireGuard());
    addTearDown(harness.container.dispose);
    final DevicesController notifier = await loaded(
      harness.container,
      harness.repository,
    );

    await notifier.connectOnLaunchIfWanted(null);

    expect(harness.repository.requestPeerCalls, 0);
  });

  test('happens once, not every time the screen comes back', () async {
    // Disconnecting and then returning to the tab is not a launch. Connecting
    // again would undo what somebody just did.
    final harness = _harness(selections: rememberedWireGuard());
    addTearDown(harness.container.dispose);
    final DevicesController notifier = await loaded(
      harness.container,
      harness.repository,
    );
    await notifier.connectOnLaunchIfWanted(_deviceId);
    await notifier.disconnect(_deviceId);

    await notifier.load();
    await notifier.connectOnLaunchIfWanted(_deviceId);

    expect(harness.tunnel.connectCalls, 1);
    expect(
      harness.container.read(devicesControllerProvider).tunnelEstablished,
      isFalse,
    );
  });
}

/// "Protected" is only ever shown over a tunnel Android actually lists.
///
/// Found on the phone: reopening the app while a tunnel was still up and
/// pressing Connect left the screen saying Protected, with no VPN at all.
void _tunnelHonestyTests() {
  const Duration interval = Duration(milliseconds: 5);

  Future<DevicesController> connectedWireGuard(
    ProviderContainer container,
    FakeServerRepository repository,
  ) async {
    repository.servers = <AvailableServer>[_wireGuardOnlyServer];
    repository.requestPeerResult = _peerResult();
    final DevicesController notifier = container.read(
      devicesControllerProvider.notifier,
    );
    await notifier.load();
    notifier.selectServer('ams-1');
    notifier.selectProfile('wg-default');
    await notifier.connect(_deviceId);
    return notifier;
  }

  Future<DevicesController> xraySelected(
    ProviderContainer container,
    FakeServerRepository repository,
  ) async {
    repository.servers = <AvailableServer>[_xrayOnlyServer];
    repository.requestXrayClientResult = _xrayClientResult();
    final DevicesController notifier = container.read(
      devicesControllerProvider.notifier,
    );
    await notifier.load();
    notifier.selectServer('ams-2');
    notifier.selectProfile('vless-xhttp-tls');
    return notifier;
  }

  test('a tunnel that goes away takes Protected with it', () async {
    final harness = _harness(watchInterval: interval);
    addTearDown(harness.container.dispose);
    await connectedWireGuard(harness.container, harness.repository);
    expect(
      harness.container.read(devicesControllerProvider).tunnelEstablished,
      isTrue,
    );

    // Torn down underneath the app, as the plugin's late shutdown did.
    harness.tunnel.vpnOwner = VpnOwner.none;
    await Future<void>.delayed(interval * 10);

    final DevicesState state = harness.container.read(
      devicesControllerProvider,
    );
    expect(state.tunnelEstablished, isFalse);
    expect(state.tunnelEstablishedAt, isNull);
    // Over, not failing: revoked on the server and shown as Off.
    expect(state.isConnected, isFalse);
    expect(harness.repository.revokePeerCalls, 1);
  });

  test("another VPN app taking over turns Nebula off completely", () async {
    final harness = _harness(watchInterval: interval);
    addTearDown(harness.container.dispose);
    await connectedWireGuard(harness.container, harness.repository);

    // v2rayNG connecting: Android revokes this tunnel and the VPN that is up
    // is now another app's.
    harness.tunnel.vpnOwner = VpnOwner.other;
    await Future<void>.delayed(interval * 10);

    final DevicesState state = harness.container.read(
      devicesControllerProvider,
    );
    expect(state.isConnected, isFalse);
    expect(state.tunnelEstablished, isFalse);
    expect(harness.repository.revokePeerCalls, 1);
    // Nothing of this app's is left to stop: Android already stopped it.
    expect(harness.tunnel.disconnectCalls, 0);
  });

  test('offline, it is still Off -- only the revoke waits', () async {
    final harness = _harness(watchInterval: interval);
    addTearDown(harness.container.dispose);
    await connectedWireGuard(harness.container, harness.repository);
    harness.repository.revokePeerError = const NebulaConnectivityException(
      'offline',
    );

    harness.tunnel.vpnOwner = VpnOwner.other;
    await Future<void>.delayed(interval * 10);

    final DevicesState state = harness.container.read(
      devicesControllerProvider,
    );
    expect(state.isConnected, isFalse);
    expect(state.actionErrorMessage, isNull);
  });

  test('a tunnel that stays up stays Protected', () async {
    final harness = _harness(watchInterval: interval);
    addTearDown(harness.container.dispose);
    await connectedWireGuard(harness.container, harness.repository);

    await Future<void>.delayed(interval * 10);

    expect(harness.tunnel.activeVpnCalls, greaterThan(1));
    expect(
      harness.container.read(devicesControllerProvider).tunnelEstablished,
      isTrue,
    );
  });

  test('a platform that cannot tell is never called disconnected', () async {
    final harness = _harness(watchInterval: interval);
    addTearDown(harness.container.dispose);
    await connectedWireGuard(harness.container, harness.repository);
    harness.tunnel.vpnOwner = null;

    await Future<void>.delayed(interval * 10);

    expect(
      harness.container.read(devicesControllerProvider).tunnelEstablished,
      isTrue,
    );
  });

  test('a WireGuard session whose server stopped answering is not left '
      'Protected', () async {
    // The interface is still up -- Android still reports this app's VPN --
    // but no handshake has succeeded for ten minutes: the server is gone and
    // every packet with it. This used to read Protected indefinitely.
    final harness = _harness(watchInterval: interval);
    addTearDown(harness.container.dispose);
    await connectedWireGuard(harness.container, harness.repository);
    harness.tunnel.latestHandshakeAt = DateTime.now().subtract(
      const Duration(minutes: 10),
    );

    await Future<void>.delayed(interval * 40);

    final DevicesState state = harness.container.read(
      devicesControllerProvider,
    );
    expect(state.tunnelEstablished, isFalse);
    // Not "Reconnecting": the one retry is spent.
    expect(
      state.actionErrorMessage,
      harness.container.read(appTextProvider).errorTunnelNoTraffic,
    );
    // One automatic attempt to bring it back, and no more: the server is
    // still not answering, so it ends Off rather than flapping.
    expect(harness.tunnel.connectCalls, 2);
    // Kept on the server, so the reconnect reused it.
    expect(harness.repository.revokePeerCalls, 0);
  });

  test('a recent handshake stays Protected', () async {
    final harness = _harness(watchInterval: interval);
    addTearDown(harness.container.dispose);
    await connectedWireGuard(harness.container, harness.repository);
    harness.tunnel.latestHandshakeAt = DateTime.now().subtract(
      const Duration(seconds: 90),
    );

    await Future<void>.delayed(interval * 10);

    expect(
      harness.container.read(devicesControllerProvider).tunnelEstablished,
      isTrue,
    );
    expect(harness.tunnel.connectCalls, 1);
  });

  test('an engine that died is restarted and Protected again', () async {
    // xray.exe or hysteria.exe exiting leaves the adapter registered; the
    // interface check alone kept showing Protected over it.
    final harness = _harness(watchInterval: interval);
    addTearDown(harness.container.dispose);
    final DevicesController notifier = await xraySelected(
      harness.container,
      harness.repository,
    );
    harness.xrayTunnel.sharedVpn = harness.tunnel;
    await notifier.connect(_deviceId);
    harness.xrayTunnel.engineAlive = false;
    harness.xrayTunnel.engineAliveAfterConnect = true;

    await Future<void>.delayed(interval * 40);

    final DevicesState state = harness.container.read(
      devicesControllerProvider,
    );
    expect(harness.xrayTunnel.connectCalls, 2);
    expect(state.tunnelEstablished, isTrue);
    expect(state.xrayClient, isNotNull);
  });

  test('an engine this platform cannot see is never called dead', () async {
    final harness = _harness(watchInterval: interval);
    addTearDown(harness.container.dispose);
    final DevicesController notifier = await xraySelected(
      harness.container,
      harness.repository,
    );
    await notifier.connect(_deviceId);
    harness.tunnel.vpnOwner = VpnOwner.own;
    harness.xrayTunnel.engineAlive = null;

    await Future<void>.delayed(interval * 10);

    expect(harness.xrayTunnel.connectCalls, 1);
    expect(
      harness.container.read(devicesControllerProvider).tunnelEstablished,
      isTrue,
    );
  });

  test('an Xray tunnel that stops carrying traffic is brought back', () async {
    // The engine runs on when its server is blocked partway through a
    // session, and the process check sees nothing wrong.
    bool carries = true;
    final harness = _harness(
      watchInterval: interval,
      trafficInterval: interval,
      tunnelCarries: (_) async => carries,
    );
    addTearDown(harness.container.dispose);
    final DevicesController notifier = await xraySelected(
      harness.container,
      harness.repository,
    );
    harness.xrayTunnel.sharedVpn = harness.tunnel;
    await notifier.connect(_deviceId);
    carries = false;

    await Future<void>.delayed(interval * 2);
    // One or two unanswered requests are a blip, not a dead tunnel.
    expect(harness.xrayTunnel.connectCalls, 1);
    expect(
      harness.container.read(devicesControllerProvider).tunnelEstablished,
      isTrue,
    );

    // The third takes it down; the reconnect finds the way open again.
    while (harness.xrayTunnel.connectCalls < 2) {
      await Future<void>.delayed(interval);
    }
    carries = true;
    await Future<void>.delayed(interval * 20);

    final DevicesState state = harness.container.read(
      devicesControllerProvider,
    );
    expect(harness.xrayTunnel.connectCalls, 2);
    expect(state.tunnelEstablished, isTrue);
    expect(harness.repository.revokePeerCalls, 0);
  });

  test(
    'a tunnel that stalls soon after connecting is caught in seconds',
    () async {
      // The once-a-minute watch is an hour here: only the quick rechecks can
      // find it.
      bool carries = true;
      final harness = _harness(
        watchInterval: interval,
        trafficInterval: const Duration(hours: 1),
        trafficRecheck: interval,
        tunnelCarries: (_) async => carries,
      );
      addTearDown(harness.container.dispose);
      final DevicesController notifier = await xraySelected(
        harness.container,
        harness.repository,
      );
      harness.xrayTunnel.sharedVpn = harness.tunnel;
      await notifier.connect(_deviceId);
      carries = false;

      for (int waited = 0; waited < 200; waited++) {
        if (harness.xrayTunnel.connectCalls >= 2) {
          break;
        }
        await Future<void>.delayed(interval);
      }
      expect(harness.xrayTunnel.connectCalls, greaterThanOrEqualTo(2));
    },
  );

  test('a route that answers but stalls a download is caught', () async {
    // The small request goes through; the 128 KB one does not. Only the soon
    // readings move data, so the once-a-minute watch is an hour here.
    bool moves = true;
    final harness = _harness(
      watchInterval: interval,
      trafficInterval: const Duration(hours: 1),
      trafficRecheck: interval,
      tunnelCarries: (_) async => true,
      tunnelMovesData: (_) async => moves,
    );
    addTearDown(harness.container.dispose);
    final DevicesController notifier = await xraySelected(
      harness.container,
      harness.repository,
    );
    harness.xrayTunnel.sharedVpn = harness.tunnel;
    await notifier.connect(_deviceId);
    moves = false;

    for (int waited = 0; waited < 200; waited++) {
      if (harness.xrayTunnel.connectCalls >= 2) {
        break;
      }
      await Future<void>.delayed(interval);
    }
    expect(harness.xrayTunnel.connectCalls, greaterThanOrEqualTo(2));
  });

  test('a second stall soon after does not say Reconnecting', () async {
    // One retry per interval: the second stall ends Off, and the screen must
    // not promise a reconnect that is not coming.
    bool carries = true;
    final harness = _harness(
      watchInterval: interval,
      trafficInterval: interval,
      tunnelCarries: (_) async => carries,
    );
    addTearDown(harness.container.dispose);
    final DevicesController notifier = await xraySelected(
      harness.container,
      harness.repository,
    );
    harness.xrayTunnel.sharedVpn = harness.tunnel;
    await notifier.connect(_deviceId);
    carries = false;
    while (harness.xrayTunnel.connectCalls < 2) {
      await Future<void>.delayed(interval);
    }
    carries = true;
    while (!harness.container
        .read(devicesControllerProvider)
        .tunnelEstablished) {
      await Future<void>.delayed(interval);
    }
    carries = false;
    for (int waited = 0; waited < 200; waited++) {
      if (!harness.container
          .read(devicesControllerProvider)
          .tunnelEstablished) {
        break;
      }
      await Future<void>.delayed(interval);
    }

    final DevicesState state = harness.container.read(
      devicesControllerProvider,
    );
    expect(harness.xrayTunnel.connectCalls, 2);
    expect(state.tunnelEstablished, isFalse);
    expect(
      state.actionErrorMessage,
      harness.container.read(appTextProvider).errorTunnelNoTraffic,
    );
  });

  test('a tunnel that stays dead ends Off with the reason', () async {
    bool carries = true;
    final harness = _harness(
      watchInterval: interval,
      trafficInterval: interval,
      tunnelCarries: (_) async => carries,
    );
    addTearDown(harness.container.dispose);
    final DevicesController notifier = await xraySelected(
      harness.container,
      harness.repository,
    );
    harness.xrayTunnel.sharedVpn = harness.tunnel;
    await notifier.connect(_deviceId);
    carries = false;

    // The reconnect waits between its own tries, in real time.
    for (int waited = 0; waited < 100; waited++) {
      await Future<void>.delayed(const Duration(milliseconds: 100));
      final DevicesState now = harness.container.read(
        devicesControllerProvider,
      );
      if (harness.xrayTunnel.connectCalls == 2 &&
          !now.isSubmitting &&
          !now.tunnelEstablished) {
        break;
      }
    }
    await Future<void>.delayed(interval * 20);

    final DevicesState state = harness.container.read(
      devicesControllerProvider,
    );
    // One attempt to bring it back, and no more.
    expect(harness.xrayTunnel.connectCalls, 2);
    expect(state.tunnelEstablished, isFalse);
    expect(
      state.actionErrorMessage,
      harness.container.read(appTextProvider).errorTunnelNoTraffic,
    );
  });

  test('an Android app off screen does not judge the tunnel', () async {
    bool carries = true;
    final harness = _harness(
      watchInterval: interval,
      trafficInterval: interval,
      trafficMeaningful: false,
      tunnelCarries: (_) async => carries,
    );
    addTearDown(harness.container.dispose);
    final DevicesController notifier = await xraySelected(
      harness.container,
      harness.repository,
    );
    harness.xrayTunnel.sharedVpn = harness.tunnel;
    await notifier.connect(_deviceId);
    carries = false;

    await Future<void>.delayed(interval * 20);

    expect(harness.xrayTunnel.connectCalls, 1);
    expect(
      harness.container.read(devicesControllerProvider).tunnelEstablished,
      isTrue,
    );
  });

  test('opening the app checks the tunnel at once', () async {
    // Off screen nothing is asked, so a tunnel that died meanwhile is found
    // when the app is opened, not three one-a-minute checks later.
    bool carries = true;
    final List<void Function()> onResume = <void Function()>[];
    final harness = _harness(
      trafficMeaningful: false,
      onResume: onResume,
      tunnelCarries: (_) async => carries,
    );
    addTearDown(harness.container.dispose);
    final DevicesController notifier = await xraySelected(
      harness.container,
      harness.repository,
    );
    harness.xrayTunnel.sharedVpn = harness.tunnel;
    await notifier.connect(_deviceId);
    carries = false;

    for (final void Function() resumed in List<void Function()>.of(onResume)) {
      resumed();
    }
    for (int waited = 0; waited < 100; waited++) {
      if (harness.xrayTunnel.connectCalls == 2) {
        break;
      }
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }

    expect(harness.xrayTunnel.connectCalls, 2);
  });

  test('a tunnel whose DNS stopped answering is brought back', () async {
    // Requests through the proxy still answered -- it looks names up
    // itself -- while no app could resolve one.
    bool resolves = true;
    final List<InternetAddress> asked = <InternetAddress>[];
    final harness = _harness(
      watchInterval: interval,
      trafficInterval: interval,
      tunnelResolves: (_, InternetAddress dns) async {
        asked.add(dns);
        return resolves;
      },
    );
    addTearDown(harness.container.dispose);
    final DevicesController notifier = await xraySelected(
      harness.container,
      harness.repository,
    );
    harness.xrayTunnel.sharedVpn = harness.tunnel;
    await notifier.connect(_deviceId);
    resolves = false;

    while (harness.xrayTunnel.connectCalls < 2) {
      await Future<void>.delayed(interval);
    }

    // The resolver the tunnel gives Android, not one of the check's own.
    expect(asked.first.address, '94.140.14.140');
  });

  test(
    'diagnostics measure through the tunnel where the app is outside it',
    () async {
      // Android keeps this app out of its own Xray VPN: measured from here,
      // the speed, loss and leak tests reported the bare line.
      final harness = _harness();
      addTearDown(harness.container.dispose);
      final DevicesController notifier = await xraySelected(
        harness.container,
        harness.repository,
      );
      expect(notifier.measurementRoute, isNull);

      await notifier.connect(_deviceId);
      expect(notifier.measurementRoute?.proxy.port, 20443);
      expect(notifier.measurementRoute?.resolver?.address, '94.140.14.140');

      await notifier.disconnect(_deviceId);
      expect(notifier.measurementRoute, isNull);
    },
  );

  test('WireGuard carries the app itself, so diagnostics go direct', () async {
    final harness = _harness();
    addTearDown(harness.container.dispose);
    final DevicesController notifier = await connectedWireGuard(
      harness.container,
      harness.repository,
    );
    expect(
      harness.container.read(devicesControllerProvider).tunnelEstablished,
      isTrue,
    );
    expect(notifier.measurementRoute, isNull);
  });

  test('a WireGuard tunnel is not asked to carry a request', () async {
    // While it is up, that is: connecting asks once, to tell a handshake
    // from a tunnel that carries something.
    bool connecting = true;
    int probes = 0;
    final harness = _harness(
      watchInterval: interval,
      trafficInterval: interval,
      tunnelCarries: (_) async {
        if (connecting) {
          return true;
        }
        probes++;
        return false;
      },
    );
    addTearDown(harness.container.dispose);
    await connectedWireGuard(harness.container, harness.repository);
    connecting = false;

    await Future<void>.delayed(interval * 20);

    expect(probes, 0);
    expect(
      harness.container.read(devicesControllerProvider).tunnelEstablished,
      isTrue,
    );
  });

  test('the watch ends with the connection', () async {
    final harness = _harness(watchInterval: interval);
    addTearDown(harness.container.dispose);
    final DevicesController notifier = await connectedWireGuard(
      harness.container,
      harness.repository,
    );
    await notifier.disconnect(_deviceId);
    final int callsAtDisconnect = harness.tunnel.activeVpnCalls;

    await Future<void>.delayed(interval * 10);

    expect(harness.tunnel.activeVpnCalls, callsAtDisconnect);
  });

  test(
    "this app's tunnel left over from before is stopped before starting",
    () async {
      final harness = _harness();
      addTearDown(harness.container.dispose);
      final DevicesController notifier = await xraySelected(
        harness.container,
        harness.repository,
      );
      // Up, and this app holds consent: it is this app's own tunnel.
      harness.tunnel.vpnOwner = VpnOwner.own;

      await notifier.connect(_deviceId);

      expect(harness.xrayTunnel.disconnectCalls, 1);
      expect(harness.xrayTunnel.connectCalls, 1);
      expect(
        harness.container.read(devicesControllerProvider).tunnelEstablished,
        isTrue,
      );
    },
  );

  test("another app's VPN is left to Android's consent dialog", () async {
    final harness = _harness();
    addTearDown(harness.container.dispose);
    final DevicesController notifier = await xraySelected(
      harness.container,
      harness.repository,
    );
    harness.tunnel.vpnOwner = VpnOwner.other;

    await notifier.connect(_deviceId);

    expect(harness.xrayTunnel.disconnectCalls, 0);
    expect(harness.tunnel.disconnectCalls, 0);
    expect(harness.xrayTunnel.requestPermissionCalls, 1);
  });

  test('nothing is stopped when no VPN is up', () async {
    final harness = _harness();
    addTearDown(harness.container.dispose);
    final DevicesController notifier = await xraySelected(
      harness.container,
      harness.repository,
    );

    await notifier.connect(_deviceId);

    expect(harness.xrayTunnel.disconnectCalls, 0);
    expect(harness.tunnel.disconnectCalls, 0);
  });
}

/// The button used to open the app and do nothing else.
void _notificationDisconnectTests() {
  Future<DevicesController> connected(
    ProviderContainer container,
    FakeServerRepository repository,
  ) async {
    repository.servers = <AvailableServer>[_xrayOnlyServer];
    repository.requestXrayClientResult = _xrayClientResult();
    final DevicesController notifier = container.read(
      devicesControllerProvider.notifier,
    );
    await notifier.load();
    notifier.selectServer('ams-2');
    notifier.selectProfile('vless-xhttp-tls');
    await notifier.connect(_deviceId);
    return notifier;
  }

  test('disconnects the way the screen does', () async {
    final harness = _harness();
    addTearDown(harness.container.dispose);
    final DevicesController notifier = await connected(
      harness.container,
      harness.repository,
    );

    await notifier.disconnectFromNotification(_deviceId);

    final DevicesState state = harness.container.read(
      devicesControllerProvider,
    );
    expect(state.isConnected, isFalse);
    expect(state.tunnelEstablished, isFalse);
    expect(harness.xrayTunnel.disconnectCalls, 1);
    expect(harness.repository.revokeXrayClientCalls, 0);
  });

  test('a tunnel left from an earlier run is stopped too', () async {
    // The app was closed with the tunnel up, and the tap is what opened it:
    // nothing in this run knows the connection, but the tunnel is real.
    final harness = _harness();
    addTearDown(harness.container.dispose);
    harness.tunnel.vpnOwner = VpnOwner.own;

    await harness.container
        .read(devicesControllerProvider.notifier)
        .disconnectFromNotification(_deviceId);

    expect(harness.xrayTunnel.disconnectCalls, 1);
    expect(harness.repository.revokeXrayClientCalls, 0);
  });

  test('opening the app to disconnect does not connect it', () async {
    final InMemorySelectionStore remembered = InMemorySelectionStore()
      ..writeServerCode('ams-1')
      ..writeProfileCode('wg-default');
    final harness = _harness(selections: remembered);
    addTearDown(harness.container.dispose);
    harness.repository.servers = <AvailableServer>[_wireGuardOnlyServer];
    harness.repository.requestPeerResult = _peerResult();
    final DevicesController notifier = harness.container.read(
      devicesControllerProvider.notifier,
    );

    await notifier.disconnectFromNotification(_deviceId);
    await notifier.load();
    await notifier.connectOnLaunchIfWanted(_deviceId);

    expect(harness.tunnel.connectCalls, 0);
  });
}

/// Reopening the app while connected used to show "Off" over a working VPN.
void _adoptionTests() {
  Future<InMemoryConnectionRecordStore> recordedXray() async {
    final InMemoryConnectionRecordStore records =
        InMemoryConnectionRecordStore();
    await records.write(
      ConnectionRecord(
        serverCode: 'ams-2',
        profileCode: 'vless-xhttp-tls',
        protocolCode: 'vless',
        sanctionsOnly: false,
        xrayClient: _xrayClientResult(),
      ),
    );
    return records;
  }

  test('reopening while connected shows the connection that is up', () async {
    final harness = _harness(records: await recordedXray());
    addTearDown(harness.container.dispose);
    harness.tunnel.vpnOwner = VpnOwner.own;
    harness.repository.servers = <AvailableServer>[
      _wireGuardOnlyServer,
      _xrayOnlyServer,
    ];

    await harness.container.read(devicesControllerProvider.notifier).load();

    final DevicesState state = harness.container.read(
      devicesControllerProvider,
    );
    expect(state.isConnected, isTrue);
    expect(state.tunnelEstablished, isTrue);
    expect(state.connectedServerCode, 'ams-2');
    expect(state.xrayClient?.uuid, _xrayClientResult().uuid);
    // Named on screen from the selection, so the selection follows the tunnel.
    expect(state.selectedServerCode, 'ams-2');
    // Nothing in this run saw it come up, so there is no clock to show.
    expect(state.tunnelEstablishedAt, isNull);
    // Listened to, not restarted.
    expect(harness.xrayTunnel.attachCalls, 1);
    expect(harness.xrayTunnel.connectCalls, 0);
    expect(harness.repository.requestXrayClientCalls, 0);
  });

  test('a reopened app checks the tunnel through its own proxy', () async {
    // This app is outside its own VPN: asked without the proxy, a request
    // proves only that the phone is online.
    const LocalProxy proxy = LocalProxy(
      port: 31337,
      username: 'nfeedfacecafebeef',
      password: 'ffeeddccbbaa99887766554433221100',
    );
    final InMemoryConnectionRecordStore records =
        InMemoryConnectionRecordStore();
    await records.write(
      ConnectionRecord(
        serverCode: 'ams-2',
        profileCode: 'vless-xhttp-tls',
        protocolCode: 'vless',
        sanctionsOnly: false,
        xrayClient: _xrayClientResult(),
        tunnelProxy: proxy,
      ),
    );
    final List<LocalProxy?> askedThrough = <LocalProxy?>[];
    final harness = _harness(
      records: records,
      trafficInterval: const Duration(milliseconds: 20),
      tunnelCarries: (LocalProxy? through) async {
        askedThrough.add(through);
        return true;
      },
    );
    addTearDown(harness.container.dispose);
    harness.tunnel.vpnOwner = VpnOwner.own;
    harness.repository.servers = <AvailableServer>[_xrayOnlyServer];

    await harness.container.read(devicesControllerProvider.notifier).load();
    await Future<void>.delayed(const Duration(milliseconds: 100));

    expect(askedThrough, isNotEmpty);
    expect(
      askedThrough.every((LocalProxy? p) => p?.port == proxy.port),
      isTrue,
    );
    expect(askedThrough.first?.password, proxy.password);
  });

  test("another app's VPN is never adopted or asked about", () async {
    // Asking whether this app held consent used to be VpnService.prepare(),
    // which for an app approved before makes it the active VPN app -- and
    // tears down whatever VPN is running. Opening this app while v2rayNG was
    // connected could disconnect v2rayNG.
    final harness = _harness(records: await recordedXray());
    addTearDown(harness.container.dispose);
    harness.tunnel.vpnOwner = VpnOwner.other;
    harness.repository.servers = <AvailableServer>[_xrayOnlyServer];

    await harness.container.read(devicesControllerProvider.notifier).load();

    expect(
      harness.container.read(devicesControllerProvider).isConnected,
      isFalse,
    );
    expect(harness.xrayTunnel.disconnectCalls, 0);
  });

  test('a record without a VPN up is not a connection', () async {
    final harness = _harness(records: await recordedXray());
    addTearDown(harness.container.dispose);
    harness.tunnel.vpnOwner = VpnOwner.none;
    harness.repository.servers = <AvailableServer>[_xrayOnlyServer];

    await harness.container.read(devicesControllerProvider.notifier).load();

    expect(
      harness.container.read(devicesControllerProvider).isConnected,
      isFalse,
    );
  });

  test("another app's VPN is not taken for this one", () async {
    final harness = _harness(records: await recordedXray());
    addTearDown(harness.container.dispose);
    harness.tunnel.vpnOwner = VpnOwner.other;
    harness.repository.servers = <AvailableServer>[_xrayOnlyServer];

    await harness.container.read(devicesControllerProvider.notifier).load();

    expect(
      harness.container.read(devicesControllerProvider).isConnected,
      isFalse,
    );
  });

  test(
    'a tunnel is recorded when it comes up and forgotten when it goes',
    () async {
      final InMemoryConnectionRecordStore records =
          InMemoryConnectionRecordStore();
      final harness = _harness(records: records);
      addTearDown(harness.container.dispose);
      harness.repository.servers = <AvailableServer>[_xrayOnlyServer];
      harness.repository.requestXrayClientResult = _xrayClientResult();
      final DevicesController notifier = harness.container.read(
        devicesControllerProvider.notifier,
      );
      await notifier.load();
      notifier.selectServer('ams-2');
      notifier.selectProfile('vless-xhttp-tls');

      await notifier.connect(_deviceId);
      final ConnectionRecord? recorded = await records.read();
      expect(recorded?.serverCode, 'ams-2');
      expect(recorded?.profileCode, 'vless-xhttp-tls');
      expect(recorded?.xrayClient?.transport, 'xhttp');

      await notifier.disconnect(_deviceId);
      expect(await records.read(), isNull);
    },
  );

  test('reopening keeps the session clock and figures of the tunnel', () async {
    // Reported from the phone: with the tunnel up all along, a reopened app
    // showed no session time and counters from zero.
    final DateTime started = DateTime.now().subtract(const Duration(hours: 2));
    final InMemoryConnectionRecordStore records =
        InMemoryConnectionRecordStore();
    await records.write(
      ConnectionRecord(
        serverCode: 'ams-2',
        profileCode: 'vless-xhttp-tls',
        protocolCode: 'vless',
        sanctionsOnly: false,
        xrayClient: _xrayClientResult(),
        establishedAt: started,
        trafficBaseline: const TunnelTraffic(rxBytes: 400, txBytes: 30),
      ),
    );
    final harness = _harness(records: records);
    addTearDown(harness.container.dispose);
    harness.tunnel.vpnOwner = VpnOwner.own;
    harness.repository.servers = <AvailableServer>[_xrayOnlyServer];

    await harness.container.read(devicesControllerProvider.notifier).load();

    final DevicesState state = harness.container.read(
      devicesControllerProvider,
    );
    expect(state.tunnelEstablished, isTrue);
    expect(
      state.tunnelEstablishedAt?.millisecondsSinceEpoch,
      started.millisecondsSinceEpoch,
    );
    expect(
      state.trafficBaseline,
      const TunnelTraffic(rxBytes: 400, txBytes: 30),
    );
  });

  test('a tunnel Android restored since the record is a new session', () async {
    final InMemoryConnectionRecordStore records =
        InMemoryConnectionRecordStore();
    await records.write(
      ConnectionRecord(
        serverCode: 'ams-2',
        profileCode: 'vless-xhttp-tls',
        protocolCode: 'vless',
        sanctionsOnly: false,
        xrayClient: _xrayClientResult(),
        establishedAt: DateTime.now().subtract(const Duration(days: 1)),
        trafficBaseline: const TunnelTraffic(rxBytes: 400, txBytes: 30),
      ),
    );
    final DateTime restored = DateTime.now().subtract(
      const Duration(minutes: 3),
    );
    final harness = _harness(
      records: records,
      restores: InMemoryTunnelRestoreStore()..restoredAt = restored,
    );
    addTearDown(harness.container.dispose);
    harness.tunnel.vpnOwner = VpnOwner.own;
    harness.repository.servers = <AvailableServer>[_xrayOnlyServer];

    await harness.container.read(devicesControllerProvider.notifier).load();

    final DevicesState state = harness.container.read(
      devicesControllerProvider,
    );
    expect(state.tunnelEstablishedAt, restored);
    expect(state.trafficBaseline, const TunnelTraffic(rxBytes: 0, txBytes: 0));
  });

  test(
    'connecting records when, and the first reading as the baseline',
    () async {
      final InMemoryConnectionRecordStore records =
          InMemoryConnectionRecordStore();
      final harness = _harness(records: records);
      addTearDown(harness.container.dispose);
      harness.repository.servers = <AvailableServer>[_xrayOnlyServer];
      harness.repository.requestXrayClientResult = _xrayClientResult();
      final DevicesController notifier = harness.container.read(
        devicesControllerProvider.notifier,
      );
      await notifier.load();
      notifier.selectServer('ams-2');
      notifier.selectProfile('vless-xhttp-tls');
      await notifier.connect(_deviceId);

      final DateTime? started = harness.container
          .read(devicesControllerProvider)
          .tunnelEstablishedAt;
      expect(started, isNotNull);
      expect(
        (await records.read())?.establishedAt?.millisecondsSinceEpoch,
        started!.millisecondsSinceEpoch,
      );

      await notifier.rememberTrafficBaseline(
        const TunnelTraffic(rxBytes: 12, txBytes: 3),
      );
      // A later reading does not move the start.
      await notifier.rememberTrafficBaseline(
        const TunnelTraffic(rxBytes: 900, txBytes: 80),
      );

      expect(
        (await records.read())?.trafficBaseline,
        const TunnelTraffic(rxBytes: 12, txBytes: 3),
      );
    },
  );

  test('no baseline is kept for a session whose start was not seen', () async {
    final harness = _harness(records: await recordedXray());
    addTearDown(harness.container.dispose);
    harness.tunnel.vpnOwner = VpnOwner.own;
    harness.repository.servers = <AvailableServer>[_xrayOnlyServer];
    final DevicesController notifier = harness.container.read(
      devicesControllerProvider.notifier,
    );
    await notifier.load();

    await notifier.rememberTrafficBaseline(
      const TunnelTraffic(rxBytes: 900, txBytes: 80),
    );

    expect(
      (await harness.container.read(connectionRecordStoreProvider).read())
          ?.trafficBaseline,
      isNull,
    );
  });

  test('Disconnect in the notification stops an adopted tunnel', () async {
    final harness = _harness(records: await recordedXray());
    addTearDown(harness.container.dispose);
    harness.tunnel.vpnOwner = VpnOwner.own;

    await harness.container
        .read(devicesControllerProvider.notifier)
        .disconnectFromNotification(_deviceId);

    expect(harness.xrayTunnel.disconnectCalls, 1);
    expect(harness.repository.revokeXrayClientCalls, 0);
  });

  group('the record itself', () {
    test('a WireGuard connection survives the round trip', () async {
      final InMemoryConnectionRecordStore records =
          InMemoryConnectionRecordStore();
      await records.write(
        ConnectionRecord(
          serverCode: 'ams-1',
          profileCode: 'wg-default',
          protocolCode: 'wireguard',
          sanctionsOnly: false,
          peer: _peerResult(),
        ),
      );

      final ConnectionRecord? read = await records.read();
      expect(read?.peer?.publicEndpoint, _peerResult().publicEndpoint);
      expect(read?.peer?.persistentKeepaliveSeconds, 25);
      expect(read?.xrayClient, isNull);
    });

    test('anything incomplete reads as no record', () {
      expect(ConnectionRecord.fromJson(null), isNull);
      expect(ConnectionRecord.fromJson('nonsense'), isNull);
      expect(
        ConnectionRecord.fromJson(<String, Object?>{'serverCode': 'ams-1'}),
        isNull,
      );
      // Neither engine, or both, cannot describe one running tunnel.
      final Map<String, Object?> both = ConnectionRecord(
        serverCode: 'ams-1',
        profileCode: 'wg-default',
        protocolCode: 'wireguard',
        sanctionsOnly: false,
        peer: _peerResult(),
      ).toJson()..['xrayClient'] = <String, Object?>{'uuid': 'x'};
      expect(ConnectionRecord.fromJson(both), isNull);
    });
  });
}

/// A SOCKS5 proxy for the apps pointed at it, instead of a VPN.
void _localProxyModeTests() {
  const int port = 20820;

  Future<void> proxyMode(InMemoryAdvancedSettingsStore store) {
    return store.write(
      AdvancedSettings.defaults.copyWith(
        connectionMode: ConnectionMode.localProxy,
        localProxyPort: port,
      ),
    );
  }

  Future<DevicesController> xraySelected(
    ProviderContainer container,
    FakeServerRepository repository,
  ) async {
    repository.servers = <AvailableServer>[_xrayOnlyServer];
    repository.requestXrayClientResult = _xrayClientResult();
    final DevicesController notifier = container.read(
      devicesControllerProvider.notifier,
    );
    await notifier.load();
    notifier.selectServer('ams-2');
    notifier.selectProfile('vless-xhttp-tls');
    return notifier;
  }

  test('runs as a proxy on the chosen port, with no VPN consent', () async {
    final harness = _harness();
    addTearDown(harness.container.dispose);
    await proxyMode(harness.advanced);
    final DevicesController notifier = await xraySelected(
      harness.container,
      harness.repository,
    );

    await notifier.connect(_deviceId);

    final DevicesState state = harness.container.read(
      devicesControllerProvider,
    );
    expect(harness.xrayTunnel.lastProxyOnly, isTrue);
    // Not a VPN, so nothing to consent to.
    expect(harness.xrayTunnel.requestPermissionCalls, 0);
    expect(state.tunnelEstablished, isTrue);
    expect(state.localProxy?.port, port);
    // The kept account, because apps are set up with it by hand.
    expect(
      state.localProxy?.username,
      InMemoryLocalProxyAccountStore().username,
    );
    expect(harness.xrayTunnel.lastConnectConfig, contains('"port":$port'));
  });

  test("a VPN connection has no proxy to show", () async {
    final harness = _harness();
    addTearDown(harness.container.dispose);
    final DevicesController notifier = await xraySelected(
      harness.container,
      harness.repository,
    );

    await notifier.connect(_deviceId);

    expect(harness.xrayTunnel.lastProxyOnly, isFalse);
    expect(
      harness.container.read(devicesControllerProvider).localProxy,
      isNull,
    );
  });

  test('a port another app holds is refused, not failed on', () async {
    // v2rayNG listening there is the obvious case: the engine could not bind
    // it, and the failure would read as nothing more than "could not connect".
    final harness = _harness(portProbe: (int probed) async => probed == port);
    addTearDown(harness.container.dispose);
    await proxyMode(harness.advanced);
    final DevicesController notifier = await xraySelected(
      harness.container,
      harness.repository,
    );

    await notifier.connect(_deviceId);

    final DevicesState state = harness.container.read(
      devicesControllerProvider,
    );
    expect(harness.xrayTunnel.connectCalls, 0);
    expect(state.tunnelEstablished, isFalse);
    expect(state.actionErrorMessage, contains('$port'));
  });

  test('WireGuard is refused rather than run as a VPN anyway', () async {
    final harness = _harness();
    addTearDown(harness.container.dispose);
    await proxyMode(harness.advanced);
    harness.repository.servers = <AvailableServer>[_wireGuardOnlyServer];
    final DevicesController notifier = harness.container.read(
      devicesControllerProvider.notifier,
    );
    await notifier.load();
    notifier.selectServer('ams-1');
    notifier.selectProfile('wg-default');

    await notifier.connect(_deviceId);

    expect(harness.tunnel.connectCalls, 0);
    expect(harness.repository.requestPeerCalls, 0);
    expect(
      harness.container.read(devicesControllerProvider).actionErrorMessage,
      isNotNull,
    );
  });

  test('a proxy that stops listening takes "Proxy on" away', () async {
    bool listening = false;
    final harness = _harness(
      watchInterval: const Duration(milliseconds: 5),
      portProbe: (int probed) async => listening,
    );
    addTearDown(harness.container.dispose);
    await proxyMode(harness.advanced);
    final DevicesController notifier = await xraySelected(
      harness.container,
      harness.repository,
    );
    await notifier.connect(_deviceId);
    listening = true;

    await Future<void>.delayed(const Duration(milliseconds: 50));
    expect(
      harness.container.read(devicesControllerProvider).tunnelEstablished,
      isTrue,
    );

    listening = false;
    await Future<void>.delayed(const Duration(milliseconds: 50));
    expect(
      harness.container.read(devicesControllerProvider).tunnelEstablished,
      isFalse,
    );
  });

  test('reopening finds a proxy still running and shows it', () async {
    final InMemoryConnectionRecordStore records =
        InMemoryConnectionRecordStore();
    await records.write(
      ConnectionRecord(
        serverCode: 'ams-2',
        profileCode: 'vless-xhttp-tls',
        protocolCode: 'vless',
        sanctionsOnly: false,
        xrayClient: _xrayClientResult(),
        localProxyPort: port,
      ),
    );
    final harness = _harness(
      records: records,
      portProbe: (int probed) async => probed == port,
    );
    addTearDown(harness.container.dispose);
    await proxyMode(harness.advanced);
    harness.repository.servers = <AvailableServer>[_xrayOnlyServer];

    await harness.container.read(devicesControllerProvider.notifier).load();

    final DevicesState state = harness.container.read(
      devicesControllerProvider,
    );
    expect(state.tunnelEstablished, isTrue);
    expect(state.localProxy?.port, port);
    expect(harness.xrayTunnel.connectCalls, 0);
  });
}

AccountSummary _account({
  int? quotaBytes,
  int? remainingBytes,
  DateTime? expiresAt,
}) {
  return AccountSummary(
    email: 'owner@example.org',
    state: 'active',
    deviceLimit: 3,
    devicesInUse: 1,
    usedBytes: 0,
    quotaBytes: quotaBytes,
    remainingBytes: remainingBytes,
    expiresAt: expiresAt,
  );
}

AccountDevice _thisDevice({
  List<String> serverCodes = const <String>['ams-2'],
}) {
  return AccountDevice(
    id: _deviceId,
    name: 'Phone',
    platform: 'android',
    state: 'active',
    clientVersion: '0.1.7',
    registeredAt: DateTime(2026, 9),
    isCurrent: true,
    serverCodes: serverCodes,
  );
}

FakeAccountRepository _accounts({
  AccountSummary? account,
  List<AccountDevice>? devices,
}) {
  return FakeAccountRepository()
    ..account = account ?? _account()
    ..devices = devices ?? <AccountDevice>[_thisDevice()];
}

void _accessTests() {
  const Duration interval = Duration(milliseconds: 5);

  Future<void> connectXray(
    ProviderContainer container,
    FakeServerRepository repository,
  ) async {
    repository.servers = <AvailableServer>[_xrayOnlyServer];
    repository.requestXrayClientResult = _xrayClientResult();
    final DevicesController notifier = container.read(
      devicesControllerProvider.notifier,
    );
    await notifier.load();
    notifier.selectServer('ams-2');
    notifier.selectProfile('vless-xhttp-tls');
    await notifier.connect(_deviceId);
  }

  // Ending waits out Android's network switch (600 ms) before it revokes, so
  // poll for the end rather than guessing a delay.
  Future<DevicesState> ended(ProviderContainer container) async {
    for (int waited = 0; waited < 150; waited++) {
      final DevicesState now = container.read(devicesControllerProvider);
      if (!now.isConnected && !now.tunnelEstablished && !now.isSubmitting) {
        break;
      }
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
    return container.read(devicesControllerProvider);
  }

  Future<void> expectEnded(
    FakeAccountRepository accounts,
    String message,
  ) async {
    final harness = _harness(accessInterval: interval, accounts: accounts);
    addTearDown(harness.container.dispose);
    await connectXray(harness.container, harness.repository);
    expect(
      harness.container.read(devicesControllerProvider).tunnelEstablished,
      isTrue,
    );

    final DevicesState state = await ended(harness.container);

    expect(state.tunnelEstablished, isFalse);
    expect(state.isConnected, isFalse);
    expect(harness.xrayTunnel.disconnectCalls, greaterThan(0));
    expect(state.actionErrorMessage, contains(message));
  }

  Future<bool> keptAfterSeveralChecks(FakeAccountRepository accounts) async {
    final harness = _harness(accessInterval: interval, accounts: accounts);
    addTearDown(harness.container.dispose);
    await connectXray(harness.container, harness.repository);
    await Future<void>.delayed(interval * 20);
    return harness.container.read(devicesControllerProvider).tunnelEstablished;
  }

  test('a link of your own is not stopped by the account', () async {
    // Signed in, a link added on this device is listed beside the server's;
    // the account's allowance and devices have nothing to do with it.
    final FakeAccountRepository accounts = _accounts(
      account: _account(quotaBytes: 30 * 1024 * 1024, remainingBytes: 0),
    );
    final harness = _harness(accessInterval: interval, accounts: accounts);
    addTearDown(harness.container.dispose);
    harness.repository.servers = <AvailableServer>[
      AvailableServer(
        code: 'free-0000abcd',
        displayName: 'Mine',
        publicHost: 'mine.example.test',
        profiles: _xrayOnlyServer.profiles,
      ),
    ];
    harness.repository.requestXrayClientResult = _xrayClientResult();
    final DevicesController notifier = harness.container.read(
      devicesControllerProvider.notifier,
    );
    await notifier.load();
    notifier.selectServer('free-0000abcd');
    notifier.selectProfile('vless-xhttp-tls');
    await notifier.connect(_deviceId);

    await Future<void>.delayed(interval * 20);

    expect(
      harness.container.read(devicesControllerProvider).tunnelEstablished,
      isTrue,
    );
    expect(accounts.fetchAccountCalls, 0);
  });

  test('in the background nobody is asked; coming back asks once', () async {
    // Two API requests every 30 seconds kept the phone's radio awake all
    // night (35 minutes of it in 2.5 hours, measured).
    final FakeAccountRepository accounts = _accounts(account: _account());
    bool inFront = false;
    final List<void Function()> resumed = <void Function()>[];
    final harness = _harness(
      accessInterval: interval,
      accounts: accounts,
      appInFront: () => inFront,
      onResume: resumed,
    );
    addTearDown(harness.container.dispose);
    await connectXray(harness.container, harness.repository);

    await Future<void>.delayed(interval * 20);
    expect(accounts.fetchAccountCalls, 0);

    inFront = true;
    for (final void Function() callback in List.of(resumed)) {
      callback();
    }
    await Future<void>.delayed(interval * 4);
    expect(accounts.fetchAccountCalls, greaterThan(0));
  });

  test('a spent allowance stops the tunnel and says why', () async {
    // What the server does to a spent account leaves the tunnel carrying
    // nothing and the screen saying Protected. Measured on the phone: twenty
    // minutes of it.
    await expectEnded(
      _accounts(
        account: _account(quotaBytes: 30 * 1024 * 1024, remainingBytes: 0),
      ),
      'Data limit reached',
    );
  });

  test('an expired account stops the tunnel and says so', () async {
    await expectEnded(
      _accounts(
        account: _account(
          expiresAt: DateTime.now().subtract(const Duration(minutes: 1)),
        ),
      ),
      'Access has expired',
    );
  });

  test('a device that lost its access to the server stops', () async {
    // An expired server grant, an admin, or the server removing it: the
    // device is still on the account and no longer holds this server.
    await expectEnded(
      _accounts(devices: <AccountDevice>[_thisDevice(serverCodes: <String>[])]),
      'Your access to this server has ended',
    );
  });

  test('a revoked credential on a server still offered is replaced', () async {
    // A saved copy of a credential the server had revoked raised a working
    // tunnel, and "access ended" followed (phone, 2026-10-30): the account
    // still had the server. Asked afresh, the server lists it again.
    final FakeAccountRepository accounts = _accounts(
      devices: <AccountDevice>[_thisDevice(serverCodes: <String>[])],
    );
    final harness = _harness(accessInterval: interval, accounts: accounts);
    addTearDown(harness.container.dispose);
    await connectXray(harness.container, harness.repository);
    harness.tunnel.vpnOwner = VpnOwner.own;
    final int asked = harness.repository.requestXrayClientCalls;

    for (int waited = 0; waited < 200; waited++) {
      if (harness.xrayTunnel.connectCalls >= 2) {
        break;
      }
      await Future<void>.delayed(interval);
    }
    accounts.devices = <AccountDevice>[_thisDevice()];
    await Future<void>.delayed(interval * 20);

    final DevicesState state = harness.container.read(
      devicesControllerProvider,
    );
    expect(harness.xrayTunnel.connectCalls, greaterThanOrEqualTo(2));
    expect(harness.repository.requestXrayClientCalls, greaterThan(asked));
    expect(state.tunnelEstablished, isTrue);
    expect(state.actionErrorMessage, isNull);
  });

  test(
    'a revoked credential takes the other saved ones of its server',
    () async {
      final FakeAccountRepository accounts = _accounts(
        devices: <AccountDevice>[_thisDevice(serverCodes: <String>[])],
      );
      final harness = _harness(accessInterval: interval, accounts: accounts);
      addTearDown(harness.container.dispose);
      AvailableProfile profile(String code) => AvailableProfile(
        code: code,
        displayName: code,
        protocolId: 'protocol-vless',
        protocolCode: 'vless',
        adBlock: false,
      );
      harness.repository.servers = <AvailableServer>[
        AvailableServer(
          code: 'ams-2',
          displayName: 'Amsterdam 2',
          publicHost: 'ams-2.example.test',
          profiles: <AvailableProfile>[
            profile('vless-xhttp-tls'),
            profile('vless-ws-tls'),
          ],
        ),
      ];
      harness.repository.requestXrayClientResult = _xrayClientResult();
      final XrayCredentialStore store = harness.container.read(
        xrayCredentialStoreProvider,
      );
      // A stale one for the protocol not in use, as from an earlier install.
      await store.write(
        serverCode: 'ams-2',
        profileCode: 'vless-ws-tls',
        credential: _xrayClientResult(),
      );
      final DevicesController notifier = harness.container.read(
        devicesControllerProvider.notifier,
      );
      await notifier.load();
      notifier.selectServer('ams-2');
      notifier.selectProfile('vless-xhttp-tls');
      await notifier.connect(_deviceId);
      harness.tunnel.vpnOwner = VpnOwner.own;

      for (int waited = 0; waited < 200; waited++) {
        if (harness.xrayTunnel.connectCalls >= 2) {
          break;
        }
        await Future<void>.delayed(interval);
      }
      accounts.devices = <AccountDevice>[_thisDevice()];

      expect(harness.xrayTunnel.connectCalls, greaterThanOrEqualTo(2));
      expect(
        await store.read(serverCode: 'ams-2', profileCode: 'vless-ws-tls'),
        isNull,
      );
    },
  );

  test('a device no longer on the account stops', () async {
    await expectEnded(
      _accounts(devices: <AccountDevice>[]),
      'Your access to this server has ended',
    );
  });

  test(
    'a rejected session stops the tunnel without asking the server',
    () async {
      // Revoked or disabled: there is no session left to revoke anything with.
      final FakeAccountRepository accounts = _accounts()
        ..accountError = const NebulaApiException(
          statusCode: 401,
          detail: 'Authentication required',
        );
      final harness = _harness(accessInterval: interval, accounts: accounts);
      addTearDown(harness.container.dispose);
      await connectXray(harness.container, harness.repository);
      // What Android reports while this app's tunnel is up.
      harness.tunnel.vpnOwner = VpnOwner.own;

      final DevicesState state = await ended(harness.container);

      expect(state.tunnelEstablished, isFalse);
      expect(state.isConnected, isFalse);
      expect(harness.xrayTunnel.disconnectCalls, greaterThan(0));
      expect(harness.repository.revokeXrayClientCalls, 0);
      expect(state.actionErrorMessage, isNull);
    },
  );

  test('with no server, nobody is asked whether access has ended', () async {
    // A build that also carries a server's address would be told "not signed
    // in", and used to take the tunnel down for it.
    final FakeAccountRepository accounts = _accounts()
      ..accountError = const NebulaApiException(
        statusCode: 401,
        detail: 'Authentication required',
      );
    final harness = _harness(
      accessInterval: interval,
      accounts: accounts,
      freeMode: true,
    );
    addTearDown(harness.container.dispose);
    await connectXray(harness.container, harness.repository);
    harness.tunnel.vpnOwner = VpnOwner.own;

    await Future<void>.delayed(interval * 20);

    expect(
      harness.container.read(devicesControllerProvider).tunnelEstablished,
      isTrue,
    );
    expect(harness.xrayTunnel.disconnectCalls, 0);
  });

  test('access with room left keeps the tunnel', () async {
    expect(
      await keptAfterSeveralChecks(
        _accounts(
          account: _account(quotaBytes: 30 * 1024 * 1024, remainingBytes: 1),
        ),
      ),
      isTrue,
    );
  });

  test('an unmetered, unexpired account keeps the tunnel', () async {
    expect(await keptAfterSeveralChecks(_accounts()), isTrue);
  });

  test('an answer that does not arrive keeps the tunnel', () async {
    // Offline, or the API busy. A tunnel is not stopped on an answer nobody
    // gave.
    final FakeAccountRepository accounts = _accounts()
      ..accountError = const NebulaConnectivityException('offline');
    expect(await keptAfterSeveralChecks(accounts), isTrue);
  });

  test('signing out disconnects first', () async {
    final harness = _harness(accounts: _accounts());
    addTearDown(harness.container.dispose);
    await connectXray(harness.container, harness.repository);

    await harness.container
        .read(devicesControllerProvider.notifier)
        .disconnectBeforeSignOut();

    final DevicesState state = harness.container.read(
      devicesControllerProvider,
    );
    expect(state.isConnected, isFalse);
    expect(harness.xrayTunnel.disconnectCalls, 1);
    // The server revokes every credential of the device on sign-out itself.
    expect(harness.repository.revokeXrayClientCalls, 0);
  });

  test('a session lost elsewhere only stops the tunnel', () async {
    final harness = _harness(accounts: _accounts());
    addTearDown(harness.container.dispose);
    await connectXray(harness.container, harness.repository);
    harness.tunnel.vpnOwner = VpnOwner.own;

    await harness.container
        .read(devicesControllerProvider.notifier)
        .endAfterSessionLost();

    final DevicesState state = harness.container.read(
      devicesControllerProvider,
    );
    expect(state.isConnected, isFalse);
    expect(state.tunnelEstablished, isFalse);
    expect(harness.xrayTunnel.disconnectCalls, greaterThan(0));
    expect(harness.repository.revokeXrayClientCalls, 0);
  });

  test('signing out while not connected does nothing', () async {
    final harness = _harness(accounts: _accounts());
    addTearDown(harness.container.dispose);

    await harness.container
        .read(devicesControllerProvider.notifier)
        .disconnectBeforeSignOut();
    await harness.container
        .read(devicesControllerProvider.notifier)
        .endAfterSessionLost();

    expect(harness.repository.revokeXrayClientCalls, 0);
    expect(harness.xrayTunnel.disconnectCalls, 0);
  });
}

void _cancelTests() {
  Future<void> until(bool Function() condition) async {
    for (int waited = 0; waited < 500 && !condition(); waited++) {
      await Future<void>.delayed(const Duration(milliseconds: 2));
    }
    expect(condition(), isTrue, reason: 'never happened');
  }

  Future<DevicesController> ready(
    ProviderContainer container,
    FakeServerRepository repository, {
    required AvailableServer server,
    required String profile,
  }) async {
    repository.servers = <AvailableServer>[server];
    final DevicesController notifier = container.read(
      devicesControllerProvider.notifier,
    );
    await notifier.load();
    notifier.selectServer(server.code);
    notifier.selectProfile(profile);
    return notifier;
  }

  test('cancelling while the server is answering goes Off at once, and '
      'revokes what the server then issues', () async {
    final harness = _harness();
    addTearDown(harness.container.dispose);
    final DevicesController notifier = await ready(
      harness.container,
      harness.repository,
      server: _xrayOnlyServer,
      profile: 'vless-xhttp-tls',
    );
    harness.repository.requestXrayClientResult = _xrayClientResult();
    final Completer<void> answer = Completer<void>();
    harness.repository.requestXrayClientGate = answer;

    final Future<void> connecting = notifier.connect(_deviceId);
    await until(() => harness.repository.requestXrayClientCalls == 1);
    expect(
      harness.container.read(devicesControllerProvider).isSubmitting,
      isTrue,
    );
    expect(notifier.canCancelConnect, isTrue);

    notifier.cancelConnect();

    // Off straight away, not when the slow answer arrives.
    final DevicesState cancelled = harness.container.read(
      devicesControllerProvider,
    );
    expect(cancelled.isSubmitting, isFalse);
    expect(cancelled.isConnected, isFalse);
    expect(notifier.canCancelConnect, isFalse);

    answer.complete();
    await connecting;

    final DevicesState after = harness.container.read(
      devicesControllerProvider,
    );
    expect(after.isConnected, isFalse);
    expect(after.tunnelEstablished, isFalse);
    expect(after.actionErrorMessage, isNull);
    expect(harness.xrayTunnel.connectCalls, 0);
    // The client the server issued after all is not left live.
    expect(harness.repository.revokeXrayClientCalls, 1);
  });

  test('cancelling while waiting for the WireGuard handshake takes the tunnel '
      'down and revokes the peer, without the no-handshake message', () async {
    final harness = _harness();
    addTearDown(harness.container.dispose);
    final DevicesController notifier = await ready(
      harness.container,
      harness.repository,
      server: _wireGuardOnlyServer,
      profile: 'wg-default',
    );
    harness.repository.requestPeerResult = _peerResult();
    harness.tunnel.handshake = false;
    final Completer<void> slowServer = Completer<void>();
    harness.tunnel.handshakeGate = slowServer;

    final Future<void> connecting = notifier.connect(_deviceId);
    await until(() => harness.tunnel.hasHandshakeCalls > 0);

    notifier.cancelConnect();
    expect(
      harness.container.read(devicesControllerProvider).isConnected,
      isFalse,
    );
    slowServer.complete();
    await connecting;

    final DevicesState after = harness.container.read(
      devicesControllerProvider,
    );
    expect(after.isConnected, isFalse);
    expect(after.actionErrorMessage, isNull);
    expect(harness.tunnel.connectCalls, 1);
    expect(harness.tunnel.disconnectCalls, greaterThan(0));
    expect(harness.repository.revokePeerCalls, 1);
    // Stood down at once rather than asking again for the whole wait.
    expect(harness.tunnel.hasHandshakeCalls, 1);
  });

  test('a request that fails after Cancel says nothing', () async {
    // The screen already says Off; an error about a connection nobody is
    // waiting for would read as a new problem.
    final harness = _harness();
    addTearDown(harness.container.dispose);
    final DevicesController notifier = await ready(
      harness.container,
      harness.repository,
      server: _xrayOnlyServer,
      profile: 'vless-xhttp-tls',
    );
    harness.repository.requestXrayClientError =
        const NebulaConnectivityException('offline');
    final Completer<void> answer = Completer<void>();
    harness.repository.requestXrayClientGate = answer;

    final Future<void> connecting = notifier.connect(_deviceId);
    await until(() => harness.repository.requestXrayClientCalls == 1);
    notifier.cancelConnect();
    answer.complete();
    await connecting;

    final DevicesState after = harness.container.read(
      devicesControllerProvider,
    );
    expect(after.actionErrorMessage, isNull);
    expect(after.isSubmitting, isFalse);
    expect(harness.repository.revokeXrayClientCalls, 0);
  });

  test('connecting again straight after Cancel waits for the undo, and '
      'keeps the new connection', () async {
    final harness = _harness();
    addTearDown(harness.container.dispose);
    final DevicesController notifier = await ready(
      harness.container,
      harness.repository,
      server: _xrayOnlyServer,
      profile: 'vless-xhttp-tls',
    );
    harness.repository.requestXrayClientResult = _xrayClientResult();
    final Completer<void> answer = Completer<void>();
    harness.repository.requestXrayClientGate = answer;

    final Future<void> first = notifier.connect(_deviceId);
    await until(() => harness.repository.requestXrayClientCalls == 1);
    notifier.cancelConnect();

    final Future<void> second = notifier.connect(_deviceId);
    expect(
      harness.container.read(devicesControllerProvider).isSubmitting,
      isTrue,
    );
    // Still waiting on the first attempt: nothing new was requested.
    expect(harness.repository.requestXrayClientCalls, 1);

    answer.complete();
    await first;
    await second;

    final DevicesState after = harness.container.read(
      devicesControllerProvider,
    );
    expect(harness.repository.revokeXrayClientCalls, 1);
    expect(harness.repository.requestXrayClientCalls, 2);
    expect(harness.xrayTunnel.connectCalls, 1);
    expect(after.isSubmitting, isFalse);
    expect(after.tunnelEstablished, isTrue);
  });

  test('there is nothing to cancel when no connect is in flight', () async {
    final harness = _harness();
    addTearDown(harness.container.dispose);
    final DevicesController notifier = await ready(
      harness.container,
      harness.repository,
      server: _xrayOnlyServer,
      profile: 'vless-xhttp-tls',
    );
    harness.repository.requestXrayClientResult = _xrayClientResult();
    expect(notifier.canCancelConnect, isFalse);

    await notifier.connect(_deviceId);
    expect(notifier.canCancelConnect, isFalse);

    notifier.cancelConnect();
    final DevicesState after = harness.container.read(
      devicesControllerProvider,
    );
    expect(after.tunnelEstablished, isTrue);
    expect(harness.repository.revokeXrayClientCalls, 0);
  });
}

/// Roadmap section 74, one condition per test, each driving the real
/// connect, fallback and protocol-test logic against [_HostileNetwork].
/// Conditions answered elsewhere: DNS poisoning and transparent DNS
/// interception (the leak test, test/core/diagnostics/leak_test_test.dart),
/// the API's own address blocked (test/core/network/route_fallback_test.dart),
/// a long connection reset mid-session (the traffic watch, "an Xray tunnel
/// that stops carrying traffic is brought back" above), and packet loss as
/// the person measures it (test/core/diagnostics/packet_loss_test.dart).
void _hostileNetworkTests() {
  Future<
    ({
      _HostileNetwork net,
      DevicesController notifier,
      ProviderContainer container,
      FakeServerRepository repository,
      FakeXrayTunnelController xray,
    })
  >
  setUp({
    _HostileNetwork? network,
    Future<bool> Function()? online,
    ServerReachCheck? reach,
  }) async {
    final _HostileNetwork net = network ?? _HostileNetwork();
    late final FakeXrayTunnelController xray;
    final harness = _harness(
      tunnelCarries: (_) async => net.carries(xray.lastConnectConfig),
      online: online,
      reach: reach,
    );
    addTearDown(harness.container.dispose);
    xray = harness.xrayTunnel;
    xray.delayFor = (String config) => net.carries(config) ? 100 : -1;
    harness.repository.servers = <AvailableServer>[_ir1];
    harness.repository.requestXrayClientResultFor = _ir1Credential;
    harness.repository.requestXrayClientResult = _ir1Credential('');
    await harness.container.read(devicesControllerProvider.notifier).load();
    final DevicesController notifier = harness.container.read(
      devicesControllerProvider.notifier,
    );
    notifier.selectServer('ir-1');
    return (
      net: net,
      notifier: notifier,
      container: harness.container,
      repository: harness.repository,
      xray: xray,
    );
  }

  DevicesState stateOf(ProviderContainer container) =>
      container.read(devicesControllerProvider);

  test(
    'UDP blocked: Hysteria2 tests -1 and Automatic connects over TCP',
    () async {
      final setup = await setUp(network: _HostileNetwork()..udpBlocked = true);

      await setup.notifier.pingProtocols(_deviceId);
      final Map<String, ProtocolDelay> delays = stateOf(
        setup.container,
      ).protocolDelays;
      expect(delays['hysteria2']?.outcome, DelayOutcome.failed);
      expect(delays['vless-tcp-tls']?.outcome, DelayOutcome.measured);
      expect(delays['vless-ws-tls']?.outcome, DelayOutcome.measured);

      await setup.notifier.connect(_deviceId);
      final DevicesState state = stateOf(setup.container);
      expect(state.tunnelEstablished, isTrue);
      expect(state.activeProfileCode, isNot('hysteria2'));
    },
  );

  test(
    'server address blocked: only the CDN route carries, and it is used',
    () async {
      final setup = await setUp(
        network: _HostileNetwork()..blocked.add('direct.example.test'),
        reach: (XrayClientResult c) async =>
            c.serverAddress == 'direct.example.test'
            ? ServerReach.unreachable
            : ServerReach.reachable,
      );

      await setup.notifier.connect(_deviceId);

      final DevicesState state = stateOf(setup.container);
      expect(state.tunnelEstablished, isTrue);
      expect(state.activeProfileCode, 'vless-ws-tls');
      // The server being unreachable is not any one protocol's fault, so
      // none is held back for it the next time.
      final Map<String, ProtocolHistory> history = setup.container
          .read(protocolHistoryStoreProvider)
          .forServer('ir-1');
      expect(history['vless-tcp-tls']?.failures ?? 0, 0);
    },
  );

  test(
    'SNI filtering: the CDN name is dropped and the direct route is used',
    () async {
      final setup = await setUp(
        network: _HostileNetwork()..blocked.add('cdn.example.test'),
      );

      await setup.notifier.connect(_deviceId);

      final DevicesState state = stateOf(setup.container);
      expect(state.tunnelEstablished, isTrue);
      expect(state.activeProfileCode, isNot('vless-ws-tls'));
    },
  );

  test('a blocked protocol is held back on the next connect', () async {
    // Blocked once, it is not the first thing tried again a minute later:
    // that would spend twenty seconds on what this network is blocking.
    final setup = await setUp(network: _HostileNetwork()..udpBlocked = true);

    await setup.notifier.connect(_deviceId);
    await setup.notifier.disconnect(_deviceId);
    final int before = setup.xray.connectCalls;
    await setup.notifier.connect(_deviceId);

    expect(setup.xray.connectCalls - before, 1);
    expect(stateOf(setup.container).activeProfileCode, isNot('hysteria2'));
  });

  test('everything blocked: it stops after four tries and says so', () async {
    final setup = await setUp(
      network: _HostileNetwork()
        ..udpBlocked = true
        ..blocked.addAll(<String>['direct.example.test', 'cdn.example.test']),
    );

    await setup.notifier.connect(_deviceId);

    final DevicesState state = stateOf(setup.container);
    expect(state.tunnelEstablished, isFalse);
    expect(setup.xray.connectCalls, lessThanOrEqualTo(4));
    expect(state.actionErrorMessage, isNotNull);
  });

  test(
    'random loss: a protocol lost on its first try is tested again',
    () async {
      final setup = await setUp(
        network: _HostileNetwork()..firstTryLost = true,
      );

      await setup.notifier.pingProtocols(_deviceId);

      final Map<String, ProtocolDelay> delays = stateOf(
        setup.container,
      ).protocolDelays;
      for (final String code in <String>[
        'hysteria2',
        'vless-tcp-tls',
        'vless-ws-tls',
      ]) {
        expect(delays[code]?.outcome, DelayOutcome.measured, reason: code);
      }
    },
  );

  test(
    'offline: it says offline and counts nothing against any protocol',
    () async {
      final setup = await setUp(
        network: _HostileNetwork()
          ..blocked.addAll(<String>['direct.example.test', 'cdn.example.test']),
        online: () async => false,
      );

      await setup.notifier.connect(_deviceId);

      expect(
        stateOf(setup.container).actionErrorMessage,
        setup.container.read(appTextProvider).errorOffline,
      );
      final Map<String, ProtocolHistory> history = setup.container
          .read(protocolHistoryStoreProvider)
          .forServer('ir-1');
      expect(
        history.values.every((ProtocolHistory h) => h.failures == 0),
        isTrue,
      );
    },
  );

  test(
    'a blockpage or interception: the certificate is named, and counted',
    () async {
      final setup = await setUp(
        network: _HostileNetwork()..blocked.add('cdn.example.test'),
        reach: (XrayClientResult c) async =>
            c.serverAddress == 'cdn.example.test'
            ? ServerReach.certificateRejected
            : ServerReach.reachable,
      );
      setup.notifier.selectProfile('vless-ws-tls');

      await setup.notifier.connect(_deviceId);

      expect(
        stateOf(setup.container).actionErrorMessage,
        setup.container.read(appTextProvider).errorServerCertificate,
      );
      final Map<String, ProtocolHistory> history = setup.container
          .read(protocolHistoryStoreProvider)
          .forServer('ir-1');
      expect(history['vless-ws-tls']?.failures, 1);
    },
  );
}
