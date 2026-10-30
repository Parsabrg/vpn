import '../../core/servers/server_repository.dart';

/// Shortens a credential for display.
///
/// `6f3b1c8e…d410` -- enough to tell two credentials apart at a glance
/// without a full secret sitting on screen in a room with other people. The
/// clipboard always gets the whole value; see [clientSummary].
///
/// A value too short to shorten is returned unchanged rather than mangled,
/// so this is safe to apply to any identifier the API might start returning.
String truncateUuid(String uuid) {
  const int head = 8;
  const int tail = 4;
  if (uuid.length <= head + tail + 1) {
    return uuid;
  }
  return '${uuid.substring(0, head)}…${uuid.substring(uuid.length - tail)}';
}

/// The text put on the clipboard from the configuration screen.
///
/// Deliberately plain `key: value` lines rather than a share link or a
/// protocol URI. The user is pasting this into another client on the same
/// phone, or into a message to someone helping them, and a format a human can
/// read is worth more there than one a machine can parse.
///
/// Pure, and separate from the widget, because what ends up on the clipboard
/// is the part worth asserting: it must carry the *full* uuid, which is
/// exactly the thing the screen deliberately does not display.
String clientSummary(XrayClientResult client) {
  final StringBuffer buffer = StringBuffer()
    ..writeln('address: ${client.serverAddress}:${client.port}')
    ..writeln('sni: ${client.sni}')
    ..writeln('transport: ${client.transport}/${client.transportSecurity}');
  final String? path = client.path;
  if (path != null) {
    buffer.writeln('path: $path');
  }
  buffer.writeln('uuid: ${client.uuid}');
  return buffer.toString();
}
