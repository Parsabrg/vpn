/// How long a server takes to answer, measured before connecting to it.
///
/// The number people actually need here is not "how far away is Amsterdam".
/// It is "does this server answer at all from my network right now", which on
/// a censored connection changes by the hour and differs between two servers
/// in the same building. A picker that lists servers without it asks the user
/// to find out by connecting to each one in turn.
///
/// Measured by opening a TCP connection to the port the client would dial and
/// timing the handshake. That is deliberately the same thing the real
/// connection does first: a port blocked by the ISP fails here in exactly the
/// way it would fail then, which is the useful signal. It is not an ICMP ping
/// -- ICMP is frequently passed while the actual port is dropped, so a ping
/// would report healthy for the one fault this exists to catch.
///
/// Nothing is sent after the handshake and nothing is read. The connection is
/// closed immediately, so this never touches the tunnel, never provisions
/// anything, and costs the user no quota.
library;

import 'dart:async';
import 'dart:io';

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../l10n/app_localizations.dart';
import '../auth/auth_notifier.dart';
import '../auth/auth_state.dart';
import 'server_repository.dart';

/// Long enough to cross a congested international link, short enough that
/// measuring a list of dead servers does not look like the app has hung.
/// A server slower than this is not one anybody would pick anyway.
const Duration kLatencyTimeout = Duration(seconds: 3);

/// How many servers are measured at once. Opening every socket simultaneously
/// is what a captive portal or an aggressive middlebox reads as a scan.
const int kLatencyConcurrency = 4;

enum LatencyStatus {
  /// Answered, and [ServerLatency.milliseconds] is set.
  reachable,

  /// Did not answer inside [kLatencyTimeout], or the connection was refused.
  /// Both are reported the same way because they mean the same thing to
  /// somebody choosing a server: this one will not work.
  unreachable,

  /// Nothing here can be measured -- every profile this server offers is UDP,
  /// or none of them publishes a port. Reported honestly rather than shown as
  /// fast, which is what a UDP connect() would produce.
  unmeasurable,
}

class ServerLatency {
  const ServerLatency.reachable(int this.milliseconds)
    : status = LatencyStatus.reachable;

  const ServerLatency.unreachable()
    : status = LatencyStatus.unreachable,
      milliseconds = null;

  const ServerLatency.unmeasurable()
    : status = LatencyStatus.unmeasurable,
      milliseconds = null;

  final LatencyStatus status;
  final int? milliseconds;

  /// Ordering key for "fastest first". Unreachable and unmeasurable servers
  /// sort to the bottom rather than being hidden: a server that is not
  /// answering right now is still one the user is entitled to and may want to
  /// try, and silently dropping it from the list would look like the account
  /// had lost access to it.
  int get sortKey => switch (status) {
    LatencyStatus.reachable => milliseconds!,
    LatencyStatus.unmeasurable => 1 << 30,
    LatencyStatus.unreachable => 1 << 31,
  };

  String label(AppText text) => switch (status) {
    LatencyStatus.reachable => text.latencyMilliseconds(milliseconds!),
    LatencyStatus.unreachable => text.latencyNoAnswer,
    LatencyStatus.unmeasurable => '--',
  };
}

/// The port to measure a server on: the first TCP profile it offers that
/// publishes one.
///
/// One number per server rather than one per profile, because the question
/// the picker is answering is which server to use. Probing every profile
/// would open several sockets to the same host to produce numbers that differ
/// by less than the noise between two runs.
int? probePortFor(AvailableServer server) {
  for (final AvailableProfile profile in server.profiles) {
    if (!profile.requiresUdp && profile.requiredPort != null) {
      return profile.requiredPort;
    }
  }
  return null;
}

/// Times a TCP handshake to [host]:[port].
Future<ServerLatency> measureEndpoint(
  String host,
  int port, {
  Duration timeout = kLatencyTimeout,
}) async {
  final Stopwatch elapsed = Stopwatch()..start();
  Socket? socket;
  try {
    socket = await Socket.connect(host, port, timeout: timeout);
    elapsed.stop();
    return ServerLatency.reachable(elapsed.elapsedMilliseconds);
  } on SocketException {
    return const ServerLatency.unreachable();
  } on TimeoutException {
    return const ServerLatency.unreachable();
  } finally {
    // destroy() rather than close(): close() waits for the peer, and there
    // is nothing to wait for -- no bytes were ever sent.
    socket?.destroy();
  }
}

Future<ServerLatency> measureServer(
  AvailableServer server, {
  Duration timeout = kLatencyTimeout,
}) async {
  final int? port = probePortFor(server);
  if (port == null) {
    return const ServerLatency.unmeasurable();
  }
  return measureEndpoint(server.publicHost, port, timeout: timeout);
}

/// Measures every server, a few at a time, and returns what answered.
Future<Map<String, ServerLatency>> measureAll(
  List<AvailableServer> servers, {
  Duration timeout = kLatencyTimeout,
  int concurrency = kLatencyConcurrency,
}) async {
  final Map<String, ServerLatency> results = <String, ServerLatency>{};
  for (int start = 0; start < servers.length; start += concurrency) {
    final List<AvailableServer> batch = servers.sublist(
      start,
      (start + concurrency).clamp(0, servers.length),
    );
    final List<ServerLatency> measured = await Future.wait(
      batch.map(
        (AvailableServer server) => measureServer(server, timeout: timeout),
      ),
    );
    for (int index = 0; index < batch.length; index++) {
      results[batch[index].code] = measured[index];
    }
  }
  return results;
}

/// What the picker reads. Empty until something asks for a measurement --
/// the list is useful without latency, and measuring on every build would
/// re-probe every server each time the screen rebuilt.
class ServerLatencyController extends Notifier<ServerLatencyState> {
  @override
  ServerLatencyState build() {
    // Listening here rather than having sign-out reach in: readings depend
    // on who is signed in, not the other way round, and a latency cache is
    // not something the auth flow should have to know exists.
    ref.listen<AuthState>(authNotifierProvider, (AuthState? _, AuthState next) {
      if (next is! AuthAuthenticated) {
        clear();
      }
    });
    return const ServerLatencyState();
  }

  Future<void> measure(List<AvailableServer> servers) async {
    if (state.isMeasuring) {
      return;
    }
    state = state.copyWith(isMeasuring: true);
    final Map<String, ServerLatency> results = await measureAll(servers);
    state = ServerLatencyState(results: results, measuredAt: DateTime.now());
  }

  /// Dropped at sign-out. These readings belong to one account's server
  /// list, and showing the next person numbers measured against servers they
  /// may not even have would be worse than showing none.
  ///
  /// Not dropped on disconnect: measuring is only offered while the tunnel is
  /// down, so every reading here was taken on the direct path and is still
  /// the right answer after a session ends.
  void clear() {
    state = const ServerLatencyState();
  }
}

class ServerLatencyState {
  const ServerLatencyState({
    this.results = const <String, ServerLatency>{},
    this.isMeasuring = false,
    this.measuredAt,
  });

  final Map<String, ServerLatency> results;
  final bool isMeasuring;
  final DateTime? measuredAt;

  bool get hasResults => results.isNotEmpty;

  ServerLatency? forServer(String code) => results[code];

  ServerLatencyState copyWith({
    Map<String, ServerLatency>? results,
    bool? isMeasuring,
    DateTime? measuredAt,
  }) {
    return ServerLatencyState(
      results: results ?? this.results,
      isMeasuring: isMeasuring ?? this.isMeasuring,
      measuredAt: measuredAt ?? this.measuredAt,
    );
  }
}

final NotifierProvider<ServerLatencyController, ServerLatencyState>
serverLatencyProvider =
    NotifierProvider<ServerLatencyController, ServerLatencyState>(
      ServerLatencyController.new,
    );

/// Servers ordered fastest first, with everything unmeasured left in the
/// order the server sent them.
List<AvailableServer> sortByLatency(
  List<AvailableServer> servers,
  ServerLatencyState latency,
) {
  if (!latency.hasResults) {
    return servers;
  }
  final List<AvailableServer> ordered = List<AvailableServer>.of(servers);
  ordered.sort((AvailableServer a, AvailableServer b) {
    final int left = latency.forServer(a.code)?.sortKey ?? (1 << 30);
    final int right = latency.forServer(b.code)?.sortKey ?? (1 << 30);
    if (left != right) {
      return left.compareTo(right);
    }
    return a.displayName.compareTo(b.displayName);
  });
  return ordered;
}
