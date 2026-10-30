import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/servers/server_repository.dart';
import 'package:nebula_mobile/core/storage/protocol_history_store.dart';
import 'package:nebula_mobile/features/devices/devices_state.dart';
import 'package:nebula_mobile/features/devices/profile_quality.dart';
import 'package:shared_preferences/shared_preferences.dart';

final DateTime now = DateTime.utc(2026, 10, 13, 12);

AvailableProfile _profile(String code) => AvailableProfile(
  code: code,
  displayName: code,
  protocolId: 'p',
  protocolCode: 'vless',
  adBlock: false,
);

List<String> _ranked(
  Map<String, ProtocolHistory> history, [
  Map<String, ProtocolDelay> delays = const <String, ProtocolDelay>{},
]) => rankByQuality(
  <AvailableProfile>[_profile('a'), _profile('b'), _profile('c')],
  history,
  delays,
  now,
).map((AvailableProfile p) => p.code).toList();

void main() {
  test('with no record the order it was given is kept', () {
    expect(_ranked(<String, ProtocolHistory>{}), <String>['a', 'b', 'c']);
  });

  test('a recent failure or drop holds a protocol back', () {
    expect(
      _ranked(<String, ProtocolHistory>{
        'a': ProtocolHistory(
          failures: 1,
          lastFailureAt: now.subtract(const Duration(minutes: 5)),
        ),
        'b': ProtocolHistory(
          drops: 1,
          lastDropAt: now.subtract(const Duration(minutes: 5)),
        ),
      }),
      <String>['c', 'b', 'a'],
    );
  });

  test('the hold ends after the cooldown', () {
    final ProtocolHistory old = ProtocolHistory(
      successes: 3,
      failures: 1,
      lastFailureAt: now.subtract(const Duration(hours: 2)),
    );
    expect(_ranked(<String, ProtocolHistory>{'c': old}), <String>[
      'c',
      'a',
      'b',
    ]);
  });

  test('XHTTP leads a long-used WebSocket, until it fails itself', () {
    List<String> rank(Map<String, ProtocolHistory> history) => rankByQuality(
      <AvailableProfile>[_profile('vless-ws-tls'), _profile('vless-xhttp-tls')],
      history,
      <String, ProtocolDelay>{},
      now,
    ).map((AvailableProfile p) => p.code).toList();
    final ProtocolHistory used = ProtocolHistory(
      successes: 20,
      lastSuccessAt: now.subtract(const Duration(hours: 1)),
    );

    expect(rank(<String, ProtocolHistory>{'vless-ws-tls': used}), <String>[
      'vless-xhttp-tls',
      'vless-ws-tls',
    ]);
    expect(
      rank(<String, ProtocolHistory>{
        'vless-ws-tls': used,
        'vless-xhttp-tls': ProtocolHistory(
          failures: 1,
          lastFailureAt: now.subtract(const Duration(minutes: 5)),
        ),
      }),
      <String>['vless-ws-tls', 'vless-xhttp-tls'],
    );
  });

  test('XHTTP that dropped and failed the test loses to one that passed', () {
    // 2026-10-29: Cloudflare from Iran set up the tunnel, then stalled it.
    final List<String> ranked = rankByQuality(
      <AvailableProfile>[_profile('vless-xhttp-tls'), _profile('vless-enc')],
      <String, ProtocolHistory>{
        'vless-xhttp-tls': ProtocolHistory(
          successes: 20,
          drops: 1,
          lastSuccessAt: now.subtract(const Duration(minutes: 10)),
          lastDropAt: now.subtract(const Duration(minutes: 5)),
        ),
      },
      <String, ProtocolDelay>{
        'vless-xhttp-tls': const ProtocolDelay.failed(),
        'vless-enc': const ProtocolDelay.measured(89),
      },
      now,
    ).map((AvailableProfile p) => p.code).toList();
    expect(ranked, <String>['vless-enc', 'vless-xhttp-tls']);
  });

  test('answering the delay test but moving no data counts as failed', () {
    expect(
      _ranked(<String, ProtocolHistory>{}, <String, ProtocolDelay>{
        'a': const ProtocolDelay.measured(90, megabits: -1),
        'b': const ProtocolDelay.measured(300, megabits: 4),
      }),
      <String>['b', 'c', 'a'],
    );
  });

  test('a recent success leads', () {
    expect(
      _ranked(<String, ProtocolHistory>{
        'c': ProtocolHistory(
          successes: 1,
          lastSuccessAt: now.subtract(const Duration(hours: 1)),
        ),
      }),
      <String>['c', 'a', 'b'],
    );
  });

  test('the last test counts: faster first, no answer last', () {
    expect(
      _ranked(<String, ProtocolHistory>{}, <String, ProtocolDelay>{
        'a': const ProtocolDelay.failed(),
        'b': const ProtocolDelay.measured(900),
        'c': const ProtocolDelay.measured(80),
      }),
      <String>['c', 'b', 'a'],
    );
  });

  test('the store keeps outcomes across a restart', () async {
    SharedPreferences.setMockInitialValues(<String, Object>{});
    final SharedPreferences preferences = await SharedPreferences.getInstance();
    await SharedPreferencesProtocolHistoryStore(
      preferences,
    ).record('s', 'a', ProtocolOutcome.drop, at: now);

    final ProtocolHistory? kept = SharedPreferencesProtocolHistoryStore(
      preferences,
    ).forServer('s')['a'];
    expect(kept?.drops, 1);
    expect(kept?.lastDropAt, now);
  });

  test('counts are halved past twenty, so old history fades', () async {
    final InMemoryProtocolHistoryStore store = InMemoryProtocolHistoryStore();
    for (int i = 0; i < 21; i++) {
      await store.record('s', 'a', ProtocolOutcome.failure, at: now);
    }
    expect(store.forServer('s')['a']!.failures, 10);
  });
}
