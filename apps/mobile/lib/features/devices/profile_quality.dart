import '../../core/servers/server_repository.dart';
import '../../core/storage/protocol_history_store.dart';
import 'devices_state.dart';

/// How long a protocol that just failed or dropped is held back. Long enough
/// that Automatic stops retrying what this network is blocking right now,
/// short enough that a block lifted in the afternoon is found again.
const Duration qualityCooldown = Duration(minutes: 30);

/// A protocol's quality on one server, from this device's own record.
///
/// Higher is better; only the order matters. What it weighs:
/// - how often a connect got traffic through, smoothed so one result does not
///   decide everything (a new protocol starts in the middle);
/// - a recent failure or drop, which holds the protocol back for
///   [qualityCooldown];
/// - a recent success, which is the best evidence it works on this network;
/// - the last protocol test: a delay measured is good, the faster the
///   better, and no answer is bad.
double qualityScore(
  ProtocolHistory? history,
  ProtocolDelay? delay,
  DateTime now,
) {
  final ProtocolHistory h = history ?? const ProtocolHistory();
  bool within(DateTime? at, Duration window) =>
      at != null && now.difference(at) < window;

  double score =
      100 * (h.successes + 1) / (h.successes + h.failures + h.drops + 2);
  if (within(h.lastFailureAt, qualityCooldown)) {
    score -= 60;
  }
  if (within(h.lastDropAt, qualityCooldown)) {
    score -= 40;
  }
  if (within(h.lastSuccessAt, const Duration(days: 1))) {
    score += 20;
  }
  if (delay != null) {
    final int? ms = delay.milliseconds;
    final double? megabits = delay.megabits;
    if (megabits != null && megabits <= 0) {
      // Answered the delay test, moved no data: as good as failed.
      score -= 30;
    } else if (delay.outcome == DelayOutcome.measured && ms != null) {
      score += 20 * (1 - (ms.clamp(0, 2000) / 2000));
    } else if (delay.outcome == DelayOutcome.failed) {
      score -= 30;
    }
  }
  return score;
}

/// [profiles] best first. Stable: equal scores keep the order they came in,
/// which is the existing delay-and-transport order.
List<AvailableProfile> rankByQuality(
  List<AvailableProfile> profiles,
  Map<String, ProtocolHistory> histories,
  Map<String, ProtocolDelay> delays,
  DateTime now,
) {
  final Map<String, double> scores = <String, double>{
    for (final AvailableProfile profile in profiles)
      profile.code:
          qualityScore(histories[profile.code], delays[profile.code], now) +
          // XHTTP first among protocols that work: through Cloudflare from
          // Iran it set up a connection in about 0.6 s where WebSocket took
          // 1.1 s, and downloaded 4.4 MB/s against 3.0 (a phone, 2026-10-14).
          // Only while nothing says it is failing here: with the bonus kept
          // after a drop or a failed test, a stalled Cloudflare route
          // outranked a direct protocol that had just passed the test, and
          // Automatic kept picking it (2026-10-29).
          (profile.code.contains('xhttp') &&
                  !_failingNow(
                    histories[profile.code],
                    delays[profile.code],
                    now,
                  )
              ? 70
              : 0),
  };
  final List<int> order = List<int>.generate(profiles.length, (int i) => i)
    ..sort((int a, int b) {
      final int byScore = scores[profiles[b].code]!.compareTo(
        scores[profiles[a].code]!,
      );
      return byScore != 0 ? byScore : a.compareTo(b);
    });
  return <AvailableProfile>[for (final int i in order) profiles[i]];
}

bool _failingNow(ProtocolHistory? h, ProtocolDelay? delay, DateTime now) {
  bool within(DateTime? at) =>
      at != null && now.difference(at) < qualityCooldown;
  return delay?.outcome == DelayOutcome.failed ||
      (delay?.megabits != null && delay!.megabits! <= 0) ||
      within(h?.lastFailureAt) ||
      within(h?.lastDropAt);
}
