import 'dart:convert';

import 'package:shared_preferences/shared_preferences.dart';

/// What happened the times this device used one protocol on one server.
///
/// Kept on the device only: nothing here is sent anywhere. Counts and times,
/// no addresses or credentials, so plain preferences are enough.
class ProtocolHistory {
  const ProtocolHistory({
    this.successes = 0,
    this.failures = 0,
    this.drops = 0,
    this.lastSuccessAt,
    this.lastFailureAt,
    this.lastDropAt,
  });

  factory ProtocolHistory.fromJson(Map<String, dynamic> json) {
    DateTime? at(String key) => json[key] == null
        ? null
        : DateTime.fromMillisecondsSinceEpoch(json[key] as int, isUtc: true);
    return ProtocolHistory(
      successes: json['s'] as int? ?? 0,
      failures: json['f'] as int? ?? 0,
      drops: json['d'] as int? ?? 0,
      lastSuccessAt: at('sa'),
      lastFailureAt: at('fa'),
      lastDropAt: at('da'),
    );
  }

  /// Connects that ended with traffic going through.
  final int successes;

  /// Connects that did not, for a reason about the protocol.
  final int failures;

  /// Tunnels the health check found carrying nothing and took down.
  final int drops;
  final DateTime? lastSuccessAt;
  final DateTime? lastFailureAt;
  final DateTime? lastDropAt;

  Map<String, dynamic> toJson() => <String, dynamic>{
    's': successes,
    'f': failures,
    'd': drops,
    if (lastSuccessAt != null) 'sa': lastSuccessAt!.millisecondsSinceEpoch,
    if (lastFailureAt != null) 'fa': lastFailureAt!.millisecondsSinceEpoch,
    if (lastDropAt != null) 'da': lastDropAt!.millisecondsSinceEpoch,
  };
}

enum ProtocolOutcome { success, failure, drop }

abstract interface class ProtocolHistoryStore {
  Map<String, ProtocolHistory> forServer(String serverCode);
  Future<void> record(
    String serverCode,
    String profileCode,
    ProtocolOutcome outcome, {
    DateTime? at,
  });
}

/// Counts are halved past this, so a protocol that failed a hundred times
/// last month is not buried forever once the network changes.
const int _countCeiling = 20;

ProtocolHistory _apply(
  ProtocolHistory history,
  ProtocolOutcome outcome,
  DateTime at,
) {
  int capped(int count) => count > _countCeiling ? count ~/ 2 : count;
  return switch (outcome) {
    ProtocolOutcome.success => ProtocolHistory(
      successes: capped(history.successes + 1),
      failures: history.failures,
      drops: history.drops,
      lastSuccessAt: at,
      lastFailureAt: history.lastFailureAt,
      lastDropAt: history.lastDropAt,
    ),
    ProtocolOutcome.failure => ProtocolHistory(
      successes: history.successes,
      failures: capped(history.failures + 1),
      drops: history.drops,
      lastSuccessAt: history.lastSuccessAt,
      lastFailureAt: at,
      lastDropAt: history.lastDropAt,
    ),
    ProtocolOutcome.drop => ProtocolHistory(
      successes: history.successes,
      failures: history.failures,
      drops: capped(history.drops + 1),
      lastSuccessAt: history.lastSuccessAt,
      lastFailureAt: history.lastFailureAt,
      lastDropAt: at,
    ),
  };
}

class SharedPreferencesProtocolHistoryStore implements ProtocolHistoryStore {
  SharedPreferencesProtocolHistoryStore(this._preferences);

  static const String _key = 'nebula.protocol_history';

  final SharedPreferences _preferences;

  Map<String, dynamic> _all() {
    try {
      final String? raw = _preferences.getString(_key);
      return raw == null
          ? <String, dynamic>{}
          : jsonDecode(raw) as Map<String, dynamic>;
    } catch (_) {
      // Unreadable history is no history: it only orders the tries.
      return <String, dynamic>{};
    }
  }

  @override
  Map<String, ProtocolHistory> forServer(String serverCode) {
    final Map<String, dynamic> server =
        (_all()[serverCode] as Map<String, dynamic>?) ?? <String, dynamic>{};
    return server.map(
      (String profile, dynamic json) => MapEntry<String, ProtocolHistory>(
        profile,
        ProtocolHistory.fromJson(json as Map<String, dynamic>),
      ),
    );
  }

  @override
  Future<void> record(
    String serverCode,
    String profileCode,
    ProtocolOutcome outcome, {
    DateTime? at,
  }) async {
    final Map<String, dynamic> all = _all();
    final Map<String, dynamic> server =
        (all[serverCode] as Map<String, dynamic>?) ?? <String, dynamic>{};
    final ProtocolHistory current = server[profileCode] == null
        ? const ProtocolHistory()
        : ProtocolHistory.fromJson(server[profileCode] as Map<String, dynamic>);
    server[profileCode] = _apply(
      current,
      outcome,
      at ?? DateTime.now().toUtc(),
    ).toJson();
    all[serverCode] = server;
    await _preferences.setString(_key, jsonEncode(all));
  }
}

/// In-memory, for tests.
class InMemoryProtocolHistoryStore implements ProtocolHistoryStore {
  final Map<String, Map<String, ProtocolHistory>> _histories =
      <String, Map<String, ProtocolHistory>>{};

  @override
  Map<String, ProtocolHistory> forServer(String serverCode) =>
      Map<String, ProtocolHistory>.of(
        _histories[serverCode] ?? <String, ProtocolHistory>{},
      );

  @override
  Future<void> record(
    String serverCode,
    String profileCode,
    ProtocolOutcome outcome, {
    DateTime? at,
  }) async {
    final Map<String, ProtocolHistory> server = _histories.putIfAbsent(
      serverCode,
      () => <String, ProtocolHistory>{},
    );
    server[profileCode] = _apply(
      server[profileCode] ?? const ProtocolHistory(),
      outcome,
      at ?? DateTime.now().toUtc(),
    );
  }
}
