/// What the live tunnel on this device has carried.
///
/// Named from **this device's** point of view, which is the opposite of every
/// figure the control plane stores: the server's `rx` is what it received, so
/// it is this device's upload. The two meet nowhere in code -- the account
/// screen's totals come from the API, this comes from the tunnel -- but a
/// reader moving between them will otherwise assume one naming and read the
/// other, so it is stated rather than implied.
library;

/// A single reading from a running tunnel.
class TunnelTraffic {
  const TunnelTraffic({
    required this.rxBytes,
    required this.txBytes,
    this.elapsed,
  });

  /// Bytes this device has received -- what a person calls "downloaded".
  final int rxBytes;

  /// Bytes this device has sent.
  final int txBytes;

  /// How long the tunnel has been up, or null when that is not knowable.
  ///
  /// Null is a real answer, not a missing one. The Xray backend reports the
  /// duration itself, so it survives the app being reopened; WireGuard does
  /// not, and a session already running when the app starts has a beginning
  /// this process never saw. Showing a clock that started when the screen
  /// opened would be a plausible number that is simply wrong.
  final Duration? elapsed;

  int get totalBytes => rxBytes + txBytes;

  @override
  bool operator ==(Object other) =>
      other is TunnelTraffic &&
      other.rxBytes == rxBytes &&
      other.txBytes == txBytes &&
      other.elapsed == elapsed;

  @override
  int get hashCode => Object.hash(rxBytes, txBytes, elapsed);

  @override
  String toString() =>
      'TunnelTraffic(rx: $rxBytes, tx: $txBytes, elapsed: $elapsed)';
}

/// Parses the `HH:MM:SS` string the Xray backend reports.
///
/// Returns null rather than zero for anything it cannot read. A tunnel that
/// has been up for hours showing `00:00:00` because the format changed is
/// worse than showing nothing, and the two are indistinguishable to a reader.
Duration? parseTunnelDuration(String value) {
  final List<String> parts = value.split(':');
  if (parts.length != 3) {
    return null;
  }
  final int? hours = int.tryParse(parts[0]);
  final int? minutes = int.tryParse(parts[1]);
  final int? seconds = int.tryParse(parts[2]);
  if (hours == null || minutes == null || seconds == null) {
    return null;
  }
  if (hours < 0 || minutes < 0 || seconds < 0) {
    return null;
  }
  return Duration(hours: hours, minutes: minutes, seconds: seconds);
}

/// `3:07:24`, or `7:24` under an hour -- the shape a stopwatch uses.
///
/// Hours are not zero-padded because they are not a fixed-width field: a
/// tunnel can be up for more than a day, and `27:14:03` is the honest
/// rendering of that rather than something that wraps back to `03:14:03`.
String formatTunnelDuration(Duration elapsed) {
  final int totalSeconds = elapsed.inSeconds;
  if (totalSeconds < 0) {
    return '0:00';
  }
  final int hours = totalSeconds ~/ 3600;
  final int minutes = (totalSeconds % 3600) ~/ 60;
  final int seconds = totalSeconds % 60;
  final String paddedSeconds = seconds.toString().padLeft(2, '0');
  if (hours == 0) {
    return '$minutes:$paddedSeconds';
  }
  return '$hours:${minutes.toString().padLeft(2, '0')}:$paddedSeconds';
}
