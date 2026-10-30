/// Measuring a server before connecting to it.
///
/// The probe is exercised against real sockets rather than a mocked one,
/// because what is being tested is whether connecting works -- the same
/// reasoning as the agent's own preflight check. A mocked socket would agree
/// with whatever the code believed.
library;

import 'dart:io';
import 'dart:ui';

import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/servers/server_latency.dart';
import 'package:nebula_mobile/core/servers/server_repository.dart';
import 'package:nebula_mobile/l10n/app_localizations.dart';

AvailableProfile _profile({
  String code = 'vless-xhttp-tls',
  String protocolCode = 'vless',
  int? requiredPort = 8445,
  bool requiresUdp = false,
}) {
  return AvailableProfile(
    code: code,
    displayName: code,
    protocolId: 'protocol-id',
    protocolCode: protocolCode,
    adBlock: false,
    requiredPort: requiredPort,
    requiresUdp: requiresUdp,
  );
}

AvailableServer _server(
  String code, {
  List<AvailableProfile>? profiles,
  String host = '127.0.0.1',
}) {
  return AvailableServer(
    code: code,
    displayName: code,
    publicHost: host,
    profiles: profiles ?? <AvailableProfile>[_profile()],
  );
}

void main() {
  group('choosing what to probe', () {
    test('picks the first TCP profile that publishes a port', () {
      final AvailableServer server = _server(
        'de-fra-1',
        profiles: <AvailableProfile>[
          _profile(code: 'hysteria2', requiredPort: 8450, requiresUdp: true),
          _profile(code: 'vless-grpc-tls', requiredPort: 8447),
        ],
      );

      expect(probePortFor(server), 8447);
    });

    test('a UDP-only server has nothing that can be measured', () {
      // A UDP socket accepts a connect() and sends into the void whether or
      // not anything is listening, so probing one would report a dead port
      // as fast -- which is worse than reporting nothing.
      final AvailableServer server = _server(
        'de-fra-1',
        profiles: <AvailableProfile>[
          _profile(code: 'hysteria2', requiredPort: 8450, requiresUdp: true),
          _profile(
            code: 'wireguard-native',
            protocolCode: 'wireguard',
            requiredPort: 51820,
            requiresUdp: true,
          ),
        ],
      );

      expect(probePortFor(server), isNull);
    });

    test('a profile without a port is skipped, not treated as port zero', () {
      final AvailableServer server = _server(
        'de-fra-1',
        profiles: <AvailableProfile>[
          _profile(code: 'wireguard-native', requiredPort: null),
          _profile(code: 'vless-ws-tls', requiredPort: 8448),
        ],
      );

      expect(probePortFor(server), 8448);
    });
  });

  group('measuring', () {
    test('a listening port answers', () async {
      final ServerSocket listener = await ServerSocket.bind('127.0.0.1', 0);
      addTearDown(() async => listener.close());
      listener.listen((Socket socket) => socket.destroy());

      final ServerLatency latency = await measureEndpoint(
        '127.0.0.1',
        listener.port,
      );

      expect(latency.status, LatencyStatus.reachable);
      expect(latency.milliseconds, isNotNull);
      expect(latency.label(lookupAppText(const Locale('en'))), endsWith('ms'));
    });

    test('a port nothing is listening on does not answer', () async {
      // The fault this whole feature exists to surface: the server is fine,
      // the port is not reachable from here. Bind one, read the number, and
      // release it, so the port is real and certainly closed.
      final ServerSocket probe = await ServerSocket.bind('127.0.0.1', 0);
      final int closedPort = probe.port;
      await probe.close();

      final ServerLatency latency = await measureEndpoint(
        '127.0.0.1',
        closedPort,
      );

      expect(latency.status, LatencyStatus.unreachable);
      expect(latency.milliseconds, isNull);
      expect(latency.label(lookupAppText(const Locale('en'))), 'no answer');
    });

    test('a host that does not resolve does not throw', () async {
      // An unroutable name is what an ISP returns for a blocked domain, so
      // this is a normal outcome here rather than an exceptional one.
      final ServerLatency latency = await measureEndpoint(
        'this-host-does-not-exist.invalid',
        443,
        timeout: const Duration(milliseconds: 800),
      );

      expect(latency.status, LatencyStatus.unreachable);
    });

    test('a UDP-only server is reported unmeasured rather than fast', () async {
      final ServerLatency latency = await measureServer(
        _server(
          'de-fra-1',
          profiles: <AvailableProfile>[
            _profile(code: 'hysteria2', requiredPort: 8450, requiresUdp: true),
          ],
        ),
      );

      expect(latency.status, LatencyStatus.unmeasurable);
      expect(latency.label(lookupAppText(const Locale('en'))), '--');
    });

    test('every server gets a reading', () async {
      final ServerSocket listener = await ServerSocket.bind('127.0.0.1', 0);
      addTearDown(() async => listener.close());
      listener.listen((Socket socket) => socket.destroy());

      final Map<String, ServerLatency> results = await measureAll(
        <AvailableServer>[
          _server(
            'up',
            profiles: <AvailableProfile>[_profile(requiredPort: listener.port)],
          ),
          _server(
            'udp-only',
            profiles: <AvailableProfile>[
              _profile(requiredPort: 8450, requiresUdp: true),
            ],
          ),
        ],
      );

      expect(results.keys.toSet(), <String>{'up', 'udp-only'});
      expect(results['up']!.status, LatencyStatus.reachable);
      expect(results['udp-only']!.status, LatencyStatus.unmeasurable);
    });

    test('more servers than the concurrency limit are all measured', () async {
      // The batching loop is the kind of index arithmetic that silently
      // drops a tail element, and a dropped server is one the picker would
      // show as unmeasured forever.
      final List<AvailableServer> servers = <AvailableServer>[
        for (int index = 0; index < kLatencyConcurrency * 2 + 1; index++)
          _server(
            'server-$index',
            profiles: <AvailableProfile>[
              _profile(requiredPort: 8450, requiresUdp: true),
            ],
          ),
      ];

      final Map<String, ServerLatency> results = await measureAll(servers);

      expect(results.length, servers.length);
    });
  });

  group('ordering', () {
    ServerLatencyState stateWith(Map<String, ServerLatency> results) {
      return ServerLatencyState(results: results);
    }

    test('fastest first', () {
      final List<AvailableServer> ordered = sortByLatency(
        <AvailableServer>[_server('slow'), _server('fast')],
        stateWith(<String, ServerLatency>{
          'slow': const ServerLatency.reachable(300),
          'fast': const ServerLatency.reachable(40),
        }),
      );

      expect(ordered.map((AvailableServer s) => s.code), <String>[
        'fast',
        'slow',
      ]);
    });

    test('unreachable servers sink but are never dropped', () {
      // The user is still entitled to them. Hiding one would look like the
      // account had lost access rather than like a port being blocked today.
      final List<AvailableServer> ordered = sortByLatency(
        <AvailableServer>[_server('dead'), _server('alive')],
        stateWith(<String, ServerLatency>{
          'dead': const ServerLatency.unreachable(),
          'alive': const ServerLatency.reachable(120),
        }),
      );

      expect(ordered.map((AvailableServer s) => s.code), <String>[
        'alive',
        'dead',
      ]);
    });

    test('unmeasurable sorts above unreachable', () {
      // "I could not test this" is a better bet than "this did not answer".
      final List<AvailableServer> ordered = sortByLatency(
        <AvailableServer>[_server('dead'), _server('untestable')],
        stateWith(<String, ServerLatency>{
          'dead': const ServerLatency.unreachable(),
          'untestable': const ServerLatency.unmeasurable(),
        }),
      );

      expect(ordered.map((AvailableServer s) => s.code), <String>[
        'untestable',
        'dead',
      ]);
    });

    test('the order the server sent is kept until something is measured', () {
      // Nothing has been measured, so there is no basis to reorder. Sorting
      // by name here would look like a measurement had happened.
      final List<AvailableServer> servers = <AvailableServer>[
        _server('zurich'),
        _server('amsterdam'),
      ];

      final List<AvailableServer> ordered = sortByLatency(
        servers,
        const ServerLatencyState(),
      );

      expect(ordered.map((AvailableServer s) => s.code), <String>[
        'zurich',
        'amsterdam',
      ]);
    });

    test('a server with no reading is not dropped from the list', () {
      final List<AvailableServer> ordered = sortByLatency(
        <AvailableServer>[_server('measured'), _server('missing')],
        stateWith(<String, ServerLatency>{
          'measured': const ServerLatency.reachable(90),
        }),
      );

      expect(ordered.length, 2);
    });
  });
}
