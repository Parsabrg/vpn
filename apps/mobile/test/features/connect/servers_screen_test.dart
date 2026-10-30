import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_riverpod/misc.dart' show Override;
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/servers/server_latency.dart';
import 'package:nebula_mobile/core/servers/server_repository.dart';
import 'package:nebula_mobile/core/storage/selection_store.dart';
import 'package:nebula_mobile/core/storage/storage_providers.dart';
import 'package:nebula_mobile/core/widgets/panel/panel_atoms.dart';
import 'package:nebula_mobile/features/connect/servers_screen.dart';
import 'package:nebula_mobile/features/devices/devices_controller.dart';
import 'package:nebula_mobile/features/devices/devices_state.dart';
import 'package:nebula_mobile/features/devices/profile_order.dart';

import '../../support/localised_app.dart';
import '../devices/fake_server_repository.dart';

AvailableProfile _profile(
  String code,
  String protocol, {
  int? requiredPort,
  bool requiresUdp = false,
}) => AvailableProfile(
  code: code,
  displayName: code,
  protocolId: protocol,
  protocolCode: protocol,
  adBlock: false,
  requiredPort: requiredPort,
  requiresUdp: requiresUdp,
);

final AvailableServer _frankfurt = AvailableServer(
  code: 'de-fra-1',
  displayName: 'Frankfurt',
  publicHost: 'fra.example.org',
  profiles: <AvailableProfile>[
    _profile('wireguard', 'wireguard'),
    _profile('vless-xhttp', 'vless'),
    _profile('hysteria2', 'hysteria2'),
  ],
);

final AvailableServer _helsinki = AvailableServer(
  code: 'fi-hel-1',
  displayName: 'Helsinki',
  publicHost: 'hel.example.org',
  profiles: <AvailableProfile>[_profile('wireguard', 'wireguard')],
);

/// Latency readings are seeded rather than measured here.
///
/// Measuring opens real sockets, and a widget test runs inside a fake-async
/// zone where real network I/O never completes -- the first version of this
/// hung for ten minutes instead of failing. What the screen owes is correct
/// rendering and ordering of readings it is given; whether the probe itself
/// works is settled against real sockets in
/// test/core/servers/server_latency_test.dart.
class _SeededLatency extends ServerLatencyController {
  _SeededLatency(this._seed);

  final ServerLatencyState _seed;

  @override
  ServerLatencyState build() => _seed;
}

Future<void> _pump(
  WidgetTester tester,
  List<AvailableServer> servers, {
  Map<String, ServerLatency>? latency,
}) async {
  final FakeServerRepository repository = FakeServerRepository()
    ..servers = servers;
  await tester.pumpWidget(
    ProviderScope(
      overrides: <Override>[
        serverRepositoryProvider.overrideWithValue(repository),
        // The devices controller remembers the last choice, which reaches
        // SharedPreferences. Overriding the store keeps this a widget test.
        selectionStoreProvider.overrideWithValue(InMemorySelectionStore()),
        if (latency != null)
          serverLatencyProvider.overrideWith(
            () => _SeededLatency(ServerLatencyState(results: latency)),
          ),
      ],
      child: localisedApp(const ServersScreen()),
    ),
  );
  await tester.pumpAndSettle();

  // The screen does not load on its own: it is pushed from a connect screen
  // that has already loaded, and refetching on push would flash the list.
  await ProviderScope.containerOf(
    tester.element(find.byType(ServersScreen)),
  ).read(devicesControllerProvider.notifier).load();
  await tester.pumpAndSettle();
}

void main() {
  group('orderedProfiles', () {
    final List<AvailableProfile> cdn = <AvailableProfile>[
      _profile('vless-grpc-tls', 'vless'),
      _profile('vless-ws-tls', 'vless'),
      _profile('vless-xhttp-tls', 'vless'),
    ];
    List<String> codes(List<AvailableProfile> list) =>
        list.map((AvailableProfile p) => p.code).toList();

    // gRPC through Cloudflare cut every large upload tried; XHTTP did not.
    test('lists gRPC last until a test says otherwise', () {
      expect(
        codes(
          orderedProfiles(cdn, const <String, ProtocolDelay>{}, pinging: false),
        ),
        <String>['vless-ws-tls', 'vless-xhttp-tls', 'vless-grpc-tls'],
      );
    });

    test('after a test: fastest first, no answer last', () {
      final Map<String, ProtocolDelay> delays = <String, ProtocolDelay>{
        'vless-grpc-tls': const ProtocolDelay.measured(120),
        'vless-ws-tls': const ProtocolDelay.failed(),
        'vless-xhttp-tls': const ProtocolDelay.measured(340),
      };

      expect(codes(orderedProfiles(cdn, delays, pinging: false)), <String>[
        'vless-grpc-tls',
        'vless-xhttp-tls',
        'vless-ws-tls',
      ]);
    });

    test('holds still while a test is running', () {
      final Map<String, ProtocolDelay> delays = <String, ProtocolDelay>{
        'vless-grpc-tls': const ProtocolDelay.measured(120),
        'vless-ws-tls': const ProtocolDelay.testing(),
        'vless-xhttp-tls': const ProtocolDelay.failed(),
      };

      expect(codes(orderedProfiles(cdn, delays, pinging: true)), <String>[
        'vless-ws-tls',
        'vless-xhttp-tls',
        'vless-grpc-tls',
      ]);
    });
  });

  testWidgets('lists every permitted server with its protocol count', (
    WidgetTester tester,
  ) async {
    await _pump(tester, <AvailableServer>[_frankfurt, _helsinki]);

    expect(find.text('2 PERMITTED'), findsOneWidget);
    expect(find.text('Frankfurt'), findsOneWidget);
    expect(find.text('de-fra-1 · 3 protocols'), findsOneWidget);
  });

  testWidgets('a server with one protocol is not "1 protocols"', (
    WidgetTester tester,
  ) async {
    await _pump(tester, <AvailableServer>[_frankfurt, _helsinki]);
    expect(find.text('fi-hel-1 · 1 protocol'), findsOneWidget);
  });

  testWidgets('choosing a server shows that server\'s protocols', (
    WidgetTester tester,
  ) async {
    await _pump(tester, <AvailableServer>[_frankfurt, _helsinki]);

    await tester.tap(find.text('Frankfurt'));
    await tester.pumpAndSettle();

    expect(find.text('PROTOCOL · FRANKFURT'), findsOneWidget);
    // Automatic first, then the server's three.
    expect(find.byType(PanelChip), findsNWidgets(4));
    expect(find.text('Use Frankfurt'), findsOneWidget);
  });

  testWidgets('switching servers clears a protocol the new one lacks', (
    WidgetTester tester,
  ) async {
    // The bug this prevents: pick vless-xhttp on Frankfurt, switch to
    // Helsinki which only offers wireguard, and connect with a profile that
    // server does not serve.
    await _pump(tester, <AvailableServer>[_frankfurt, _helsinki]);

    await tester.tap(find.text('Frankfurt'));
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(PanelChip, 'vless-xhttp'));
    await tester.pumpAndSettle();

    PanelChip chipFor(String label) =>
        tester.widget<PanelChip>(find.widgetWithText(PanelChip, label));
    expect(chipFor('vless-xhttp').selected, isTrue);

    await tester.tap(find.text('Helsinki'));
    await tester.pumpAndSettle();

    expect(find.byType(PanelChip), findsNWidgets(2));
    expect(chipFor('wireguard').selected, isFalse);
    // The app chooses until the person does.
    expect(chipFor('Automatic').selected, isTrue);
  });

  testWidgets('the action names the server it will use', (
    WidgetTester tester,
  ) async {
    await _pump(tester, <AvailableServer>[_frankfurt, _helsinki]);
    await tester.tap(find.text('Helsinki'));
    await tester.pumpAndSettle();
    expect(find.text('Use Helsinki'), findsOneWidget);
  });

  testWidgets('no latency is shown until something has been measured', (
    WidgetTester tester,
  ) async {
    // The design puts a figure here, and the list is useful without one.
    // Filling it in before anybody asked would make a number that was never
    // measured look measured.
    await _pump(tester, <AvailableServer>[_frankfurt]);

    expect(find.textContaining('ms'), findsNothing);
    // One for the servers, one for the protocols of the server chosen: a
    // single server is chosen for the person.
    expect(find.text('Test'), findsNWidgets(2));
  });

  testWidgets('readings are shown and the fastest is listed first', (
    WidgetTester tester,
  ) async {
    await _pump(
      tester,
      <AvailableServer>[_frankfurt, _helsinki],
      latency: <String, ServerLatency>{
        'de-fra-1': const ServerLatency.reachable(210),
        'fi-hel-1': const ServerLatency.reachable(35),
      },
    );

    expect(find.text('210 ms'), findsOneWidget);
    expect(find.text('35 ms'), findsOneWidget);
    expect(
      tester.getTopLeft(find.text('Helsinki')).dy,
      lessThan(tester.getTopLeft(find.text('Frankfurt')).dy),
    );
    expect(find.text('Test again'), findsOneWidget);
  });

  testWidgets('a server that did not answer sinks but stays listed', (
    WidgetTester tester,
  ) async {
    // The user is still entitled to it. Dropping it would look like the
    // account had lost access rather than like a port being blocked today.
    await _pump(
      tester,
      <AvailableServer>[_frankfurt, _helsinki],
      latency: <String, ServerLatency>{
        'de-fra-1': const ServerLatency.reachable(90),
        'fi-hel-1': const ServerLatency.unreachable(),
      },
    );

    expect(find.text('Helsinki'), findsOneWidget);
    expect(find.text('no answer'), findsOneWidget);
    expect(
      tester.getTopLeft(find.text('Frankfurt')).dy,
      lessThan(tester.getTopLeft(find.text('Helsinki')).dy),
    );
  });

  testWidgets('a server nothing can measure shows no figure', (
    WidgetTester tester,
  ) async {
    // A UDP connect() succeeds against nothing at all, so a number here
    // would report a dead port as instant.
    await _pump(
      tester,
      <AvailableServer>[_frankfurt],
      latency: <String, ServerLatency>{
        'de-fra-1': const ServerLatency.unmeasurable(),
      },
    );

    expect(find.text('--'), findsOneWidget);
    expect(find.textContaining('ms'), findsNothing);
  });
}
