import '../routing/tunnel_routes.dart';
import '../servers/server_repository.dart';

/// Renders a standard WireGuard `.conf` (the same text format both the
/// Android [Config.parse] call and the Windows `wireguard.exe
/// /installtunnelservice` file expect) from this device's already-generated
/// local private key and the peer the control plane just provisioned.
String renderWireGuardConfig({
  required String privateKeyBase64,
  required WireGuardPeerResult peer,
  bool bypassLocalNetwork = false,
}) {
  final StringBuffer buffer = StringBuffer()
    ..writeln('[Interface]')
    ..writeln('PrivateKey = $privateKeyBase64')
    ..writeln('Address = ${peer.assignedAddress}/32')
    ..writeln('DNS = ${peer.clientDns}')
    ..writeln()
    ..writeln('[Peer]')
    ..writeln('PublicKey = ${peer.serverPublicKey}')
    ..writeln('Endpoint = ${peer.publicEndpoint}')
    ..writeln(
      'AllowedIPs = '
      '${allowedIpsFor(peer.clientAllowedIps, bypassLocalNetwork: bypassLocalNetwork)}',
    )
    ..writeln('PersistentKeepalive = ${peer.persistentKeepaliveSeconds}');
  return buffer.toString();
}

/// Adds the Android-only `ExcludedApplications` key to a rendered config.
///
/// Separate from [renderWireGuardConfig] because this key is understood by
/// wireguard-android's parser and by nothing else. The Windows client parses
/// the same text with `wireguard.exe`, which rejects keys it does not know --
/// so emitting it unconditionally would turn split tunnelling on one platform
/// into a tunnel that will not start on another.
///
/// Returns the config unchanged when there is nothing to exclude, rather than
/// an empty key: `ExcludedApplications = ` is not the same as absent, and the
/// parser is entitled to treat it as a malformed line.
String withExcludedApplications(
  String configText,
  List<String> excludedPackages,
) {
  if (excludedPackages.isEmpty) {
    return configText;
  }
  const String marker = '[Peer]';
  final int peerIndex = configText.indexOf(marker);
  final String line = 'ExcludedApplications = ${excludedPackages.join(', ')}\n';
  // The key belongs to [Interface]; appending it to the end of the file would
  // put it under [Peer], where it means nothing and is silently ignored.
  if (peerIndex < 0) {
    return '$configText$line';
  }
  final String head = configText.substring(0, peerIndex);
  final String tail = configText.substring(peerIndex);
  return '$head$line\n$tail';
}

/// The `AllowedIPs` value, narrowed to leave the local network direct.
///
/// In WireGuard this is the client's own routing decision -- the server sends
/// what it thinks the client should route, and the client decides what it
/// actually claims. Narrowing it is safe; widening it is not.
///
/// So the bypass applies only where the server asked for the whole space. A
/// server that sent a narrower list has already made a routing decision of its
/// own, and substituting the computed complement there could *widen* what the
/// tunnel takes -- which is the one direction this must never move.
String allowedIpsFor(String configured, {required bool bypassLocalNetwork}) {
  final List<String> entries = configured
      .split(',')
      .map((String entry) => entry.trim())
      .where((String entry) => entry.isNotEmpty)
      .toList();
  if (!bypassLocalNetwork || !entries.contains('0.0.0.0/0')) {
    return entries.join(', ');
  }
  final List<String> narrowed = <String>[];
  for (final String entry in entries) {
    if (entry == '0.0.0.0/0') {
      narrowed.addAll(ipv4RoutesExcluding(kLocalRanges));
    } else {
      narrowed.add(entry);
    }
  }
  return narrowed.join(', ');
}
