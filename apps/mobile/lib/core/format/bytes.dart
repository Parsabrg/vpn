/// Formatting byte counts for a screen people read at a glance.
///
/// Binary units throughout, because that is what the servers count in and
/// what every other VPN client shows. Mixing the two conventions is how a
/// "1 GB" allowance becomes an argument about 7% of a gigabyte.
library;

const int _kib = 1024;
const int _mib = _kib * 1024;
const int _gib = _mib * 1024;
const int _tib = _gib * 1024;

/// A short, human figure: `412 GB`, `1.4 GB`, `860 MB`, `0 B`.
///
/// One decimal place below ten and none above, because the leading digits are
/// what a person actually reads and `412.7 GB` is no more useful than `412 GB`
/// while being wider and noisier in a column of figures.
String formatBytes(int bytes) {
  if (bytes < 0) {
    return '0 B';
  }
  if (bytes < _kib) {
    return '$bytes B';
  }
  final (double value, String unit) = switch (bytes) {
    < _mib => (bytes / _kib, 'KB'),
    < _gib => (bytes / _mib, 'MB'),
    < _tib => (bytes / _gib, 'GB'),
    _ => (bytes / _tib, 'TB'),
  };
  final String rendered = value < 10
      ? value.toStringAsFixed(1)
      : value.toStringAsFixed(0);
  return '$rendered $unit';
}

/// `612 / 1024 GB` -- the pair the design shows under the quota bar.
///
/// Both figures are rendered in the larger of the two units so they can be
/// compared at a glance. Formatting them independently would produce
/// "860 MB / 1.0 GB", which is a subtraction the reader should not have to do.
String formatBytePair(int used, int total) {
  // The unit comes from what has been used, not the total. A 1 TiB quota is
  // exactly 1024 GiB, and choosing by the total would render the design's
  // "612 / 1024 GB" as "0.6 / 1 TB" -- technically the same figure, and far
  // harder to read. Falling back to the total when nothing has been used
  // keeps a fresh account from showing "0 / 1073741824 KB".
  final int scale = used > 0 ? used : total;
  final String unit = switch (scale) {
    < _mib => 'KB',
    < _gib => 'MB',
    < _tib => 'GB',
    _ => 'TB',
  };
  final int divisor = switch (unit) {
    'KB' => _kib,
    'MB' => _mib,
    'GB' => _gib,
    _ => _tib,
  };

  String scaled(int bytes) {
    final double value = bytes / divisor;
    return value < 10 && value != value.roundToDouble()
        ? value.toStringAsFixed(1)
        : value.toStringAsFixed(0);
  }

  return '${scaled(used)} / ${scaled(total)} $unit';
}
