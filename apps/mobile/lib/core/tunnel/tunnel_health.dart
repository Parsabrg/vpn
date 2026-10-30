/// Whether the thing actually carrying traffic is still alive.
///
/// "Protected" used to rest on one question: is this app's VPN interface
/// (Android) or adapter (Windows) still up. An interface can outlive the
/// engine behind it -- a WireGuard session whose peer stopped answering, an
/// `xray.exe` or `hysteria.exe` that crashed while the adapter stayed
/// registered -- and every packet then goes nowhere while the screen says
/// Protected. These are the engine-level checks the tunnel watch adds.
library;

/// What a check found. [unknown] is never acted on: a tunnel is not torn
/// down on an answer nobody could get.
enum EngineHealth { alive, dead, unknown }

/// How long a WireGuard session can go without a handshake and still be
/// carrying traffic.
///
/// WireGuard rekeys every two minutes while packets flow -- and the
/// persistent keepalive keeps them flowing -- and refuses a session older
/// than three. So a latest handshake more than three minutes old means no
/// rekey succeeded: the server stopped answering. Thirty seconds of margin
/// for a rekey that is merely slow.
const Duration wireguardSessionLimit = Duration(minutes: 3, seconds: 30);

/// Judges a WireGuard tunnel by its latest handshake.
///
/// [latestHandshake] is null when the platform could not say, and the Unix
/// epoch when no handshake has ever completed.
EngineHealth wireguardHealth(DateTime? latestHandshake, DateTime now) {
  if (latestHandshake == null) {
    return EngineHealth.unknown;
  }
  if (latestHandshake.millisecondsSinceEpoch <= 0) {
    return EngineHealth.dead;
  }
  return now.difference(latestHandshake) > wireguardSessionLimit
      ? EngineHealth.dead
      : EngineHealth.alive;
}

/// Judges an Xray or Hysteria2 engine by whether its process is running.
EngineHealth engineProcessHealth(bool? running) => switch (running) {
  true => EngineHealth.alive,
  false => EngineHealth.dead,
  null => EngineHealth.unknown,
};

/// Parses `wg show INTERFACE latest-handshakes`: one line per peer, its
/// public key and a Unix time in seconds separated by a tab, `0` for a peer
/// that never completed one. The newest across peers, or null when the
/// output holds no peer at all.
DateTime? parseLatestHandshakes(String output) {
  int? newest;
  for (final String line in output.split('\n')) {
    final List<String> fields = line.trim().split(RegExp(r'\s+'));
    if (fields.length != 2) {
      continue;
    }
    final int? seconds = int.tryParse(fields[1]);
    if (seconds == null) {
      continue;
    }
    if (newest == null || seconds > newest) {
      newest = seconds;
    }
  }
  return newest == null
      ? null
      : DateTime.fromMillisecondsSinceEpoch(newest * 1000, isUtc: true);
}
