import '../../core/servers/server_repository.dart';
import 'devices_state.dart';

/// The order a server's protocols are listed in.
///
/// Before a test: as the server sends them, except gRPC last. Through
/// Cloudflare gRPC cut every large upload tried -- 100 MB, reset after
/// 10-16 s, three times out of three -- where XHTTP on the same address
/// delivered all four. It stays listed; it is no longer the first choice.
///
/// Once a test has finished, fastest first and no answer last, as v2ray
/// sorts. Not while one is running, or the chips would move under a finger.
List<AvailableProfile> orderedProfiles(
  List<AvailableProfile> profiles,
  Map<String, ProtocolDelay> delays, {
  required bool pinging,
}) {
  int rank(AvailableProfile profile) {
    final ProtocolDelay? delay = delays[profile.code];
    if (pinging || delay == null || delay.outcome == DelayOutcome.testing) {
      return 0;
    }
    return delay.outcome == DelayOutcome.measured ? 0 : 1;
  }

  final List<AvailableProfile> ordered = <AvailableProfile>[...profiles];
  final Map<AvailableProfile, int> position = <AvailableProfile, int>{
    for (int i = 0; i < profiles.length; i++) profiles[i]: i,
  };
  final bool sortByDelay = !pinging && delays.isNotEmpty;
  ordered.sort((AvailableProfile a, AvailableProfile b) {
    if (sortByDelay) {
      final int byOutcome = rank(a).compareTo(rank(b));
      if (byOutcome != 0) {
        return byOutcome;
      }
      final int? msA = delays[a.code]?.milliseconds;
      final int? msB = delays[b.code]?.milliseconds;
      if (msA != null && msB != null && msA != msB) {
        return msA.compareTo(msB);
      }
    }
    final bool grpcA = a.code.contains('grpc');
    final bool grpcB = b.code.contains('grpc');
    if (grpcA != grpcB) {
      return grpcA ? 1 : -1;
    }
    // List.sort is not stable: the server's own order breaks ties.
    return position[a]!.compareTo(position[b]!);
  });
  return ordered;
}
