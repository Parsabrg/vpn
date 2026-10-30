import 'dart:convert';

import 'server_repository.dart';

/// A connection somebody made elsewhere and shared as a link: a Cloudflare
/// Worker's `vless://`, typically (roadmap 28), or a line of a subscription.
typedef ImportedProfile = ({String name, XrayClientResult client});

final RegExp _uuid = RegExp(
  r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$',
);

const Map<String, String> _transports = <String, String>{
  'ws': 'websocket',
  'xhttp': 'xhttp',
  'splithttp': 'xhttp',
  'grpc': 'grpc',
  'tcp': 'raw',
  'raw': 'raw',
};

/// The Shadowsocks ciphers Xray-core speaks, under the names it uses.
/// Stream ciphers and `none` are refused: neither protects anything.
const Map<String, String> _ssMethods = <String, String>{
  'aes-128-gcm': 'aes-128-gcm',
  'aes-256-gcm': 'aes-256-gcm',
  'chacha20-poly1305': 'chacha20-poly1305',
  'chacha20-ietf-poly1305': 'chacha20-poly1305',
  'xchacha20-poly1305': 'xchacha20-poly1305',
  'xchacha20-ietf-poly1305': 'xchacha20-poly1305',
  '2022-blake3-aes-128-gcm': '2022-blake3-aes-128-gcm',
  '2022-blake3-aes-256-gcm': '2022-blake3-aes-256-gcm',
  '2022-blake3-chacha20-poly1305': '2022-blake3-chacha20-poly1305',
};

/// Reads any link this app can connect with, or null.
///
/// Strict on purpose: a link read loosely becomes a tunnel that comes up and
/// carries nothing, or one that quietly drops a protection the link asked
/// for. What the config this app writes cannot express is refused, never
/// approximated -- and certificate checks are never turned off, so a link
/// asking for `insecure`/`allowInsecure` is refused rather than obeyed.
ImportedProfile? parseLink(String text) {
  final String trimmed = text.trim();
  final int colon = trimmed.indexOf('://');
  if (colon <= 0) {
    return null;
  }
  return switch (trimmed.substring(0, colon).toLowerCase()) {
    'vless' => parseVlessLink(trimmed),
    'trojan' => _parseTrojan(trimmed),
    'ss' => _parseShadowsocks(trimmed),
    'hysteria2' || 'hy2' => _parseHysteria2(trimmed),
    _ => null,
  };
}

/// The link's Encrypted Client Hello setting (Xray's `echConfigList`), as
/// v2rayN and v2rayNG write it: `ech=cloudflare-ech.com+udp://1.1.1.1`.
/// Dropped, a Cloudflare link carried nothing from Iran where the same link
/// worked in v2rayN (2026-10-14).
String? _ech(Map<String, String> query) {
  final String value = (query['ech'] ?? '').trim();
  return value.isEmpty ? null : value;
}

bool _insecure(Map<String, String> query) =>
    <String>['insecure', 'allowInsecure', 'allow_insecure'].any(
      (String key) => <String>{'1', 'true'}.contains(query[key]?.toLowerCase()),
    );

String _nameOf(Uri link, String fallback) {
  final String name = Uri.decodeComponent(link.fragment).trim();
  return name.isEmpty ? fallback : name;
}

/// Port from the link, refusing what `Uri` would silently turn into 443:
/// ":0", and a port range for Hysteria2 port hopping.
int? _port(Uri link, String text, {int fallback = 443}) {
  if (RegExp(r'@[^/?#]*:0+([/?#]|$)').hasMatch(text)) {
    return null;
  }
  final int port = link.hasPort ? link.port : fallback;
  return port > 0 && port <= 65535 ? port : null;
}

/// The TLS name and the `Host` a TLS link connects with, or null when they
/// differ -- the config this app writes sends one name for both.
String? _sniFor(Map<String, String> query, String address) {
  final String host = query['host'] ?? '';
  final String sni = switch (query['sni'] ?? query['peer'] ?? '') {
    '' => host.isEmpty ? address : host,
    final String named => named,
  };
  if (host.isNotEmpty && host.toLowerCase() != sni.toLowerCase()) {
    return null;
  }
  return sni;
}

/// Reads a `vless://` link: WebSocket, XHTTP or gRPC inside TLS, raw TCP
/// inside TLS, or raw TCP inside REALITY (with or without the Vision flow).
ImportedProfile? parseVlessLink(String text) {
  final Uri? link = Uri.tryParse(text.trim());
  if (link == null || link.scheme.toLowerCase() != 'vless') {
    return null;
  }
  final String id = Uri.decodeComponent(link.userInfo);
  final String address = link.host;
  final int? port = _port(link, text.trim());
  if (!_uuid.hasMatch(id) || address.isEmpty || port == null) {
    return null;
  }
  final Map<String, String> query = link.queryParameters;
  final String? transport = _transports[(query['type'] ?? 'tcp').toLowerCase()];
  final String security = (query['security'] ?? '').toLowerCase();
  final String flow = query['flow'] ?? '';
  if (transport == null ||
      (query['encryption'] ?? 'none') != 'none' ||
      _insecure(query) ||
      !<String>{'tls', 'reality'}.contains(security) ||
      // Vision runs on raw TCP only; any other flow is refused.
      (flow.isNotEmpty && (flow != 'xtls-rprx-vision' || transport != 'raw'))) {
    return null;
  }
  final String path = query['path'] ?? '';
  if (security == 'reality') {
    final String publicKey = query['pbk'] ?? '';
    final String sni = query['sni'] ?? '';
    // REALITY borrows another site's name; without both it has nothing to
    // present and nothing to check.
    if (transport != 'raw' || publicKey.isEmpty || sni.isEmpty) {
      return null;
    }
    return (
      name: _nameOf(link, address),
      client: XrayClientResult(
        clientId: 'imported',
        uuid: id.toLowerCase(),
        serverAddress: address,
        port: port,
        sni: sni,
        transport: 'raw',
        transportSecurity: 'reality',
        adBlock: false,
        flow: flow.isEmpty ? null : flow,
        realityPublicKey: publicKey,
        realityShortId: query['sid'] ?? '',
        fingerprint: query['fp'],
      ),
    );
  }
  final String? sni = _sniFor(query, address);
  if (sni == null) {
    return null;
  }
  return (
    name: _nameOf(link, sni),
    client: XrayClientResult(
      // Nothing on a server answers to this; it only has to be stable.
      clientId: 'imported',
      uuid: id.toLowerCase(),
      serverAddress: address,
      port: port,
      sni: sni,
      transport: transport,
      transportSecurity: 'tls',
      adBlock: false,
      flow: flow.isEmpty ? null : flow,
      path: switch (transport) {
        'grpc' || 'raw' => null,
        _ => path.isEmpty ? '/' : path,
      },
      serviceName: transport == 'grpc' ? (query['serviceName'] ?? '') : null,
      echConfigList: _ech(query),
    ),
  );
}

/// `trojan://password@host:port?type=ws&sni=...#name`: always TLS.
ImportedProfile? _parseTrojan(String text) {
  final Uri? link = Uri.tryParse(text);
  if (link == null) {
    return null;
  }
  final String password = Uri.decodeComponent(link.userInfo);
  final String address = link.host;
  final int? port = _port(link, text);
  final Map<String, String> query = link.queryParameters;
  final String? transport = _transports[(query['type'] ?? 'tcp').toLowerCase()];
  final String security = (query['security'] ?? 'tls').toLowerCase();
  if (password.isEmpty ||
      address.isEmpty ||
      port == null ||
      transport == null ||
      security != 'tls' ||
      _insecure(query)) {
    return null;
  }
  final String? sni = _sniFor(query, address);
  if (sni == null) {
    return null;
  }
  final String path = query['path'] ?? '';
  return (
    name: _nameOf(link, sni),
    client: XrayClientResult(
      clientId: 'imported',
      uuid: '',
      protocol: 'trojan',
      password: password,
      serverAddress: address,
      port: port,
      sni: sni,
      transport: transport,
      transportSecurity: 'tls',
      adBlock: false,
      path: switch (transport) {
        'grpc' || 'raw' => null,
        _ => path.isEmpty ? '/' : path,
      },
      serviceName: transport == 'grpc' ? (query['serviceName'] ?? '') : null,
      echConfigList: _ech(query),
    ),
  );
}

String? _base64Text(String text) {
  String compact = text.replaceAll('-', '+').replaceAll('_', '/');
  compact = compact.padRight((compact.length + 3) ~/ 4 * 4, '=');
  try {
    return utf8.decode(base64.decode(compact));
  } on FormatException {
    return null;
  }
}

/// `ss://`, in SIP002 form (`ss://base64(method:password)@host:port`, or
/// the user info in plain text) or the older all-Base64 form. A plugin is
/// refused: the app runs none.
ImportedProfile? _parseShadowsocks(String text) {
  String body = text.substring(text.indexOf('://') + 3);
  final int hash = body.indexOf('#');
  final String fragment = hash >= 0 ? body.substring(hash) : '';
  if (hash >= 0) {
    body = body.substring(0, hash);
  }
  if (!body.contains('@')) {
    // Old form: everything before the name is Base64.
    final String? decoded = _base64Text(body.split('?').first);
    if (decoded == null) {
      return null;
    }
    body = decoded;
  }
  final Uri? link = Uri.tryParse('ss://$body$fragment');
  if (link == null || link.queryParameters.containsKey('plugin')) {
    return null;
  }
  String userInfo = Uri.decodeComponent(link.userInfo);
  if (!userInfo.contains(':')) {
    userInfo = _base64Text(userInfo) ?? '';
  }
  final int split = userInfo.indexOf(':');
  final String? method = split > 0
      ? _ssMethods[userInfo.substring(0, split).toLowerCase()]
      : null;
  final String password = split > 0 ? userInfo.substring(split + 1) : '';
  final int? port = link.hasPort ? link.port : null;
  if (method == null || password.isEmpty || link.host.isEmpty || port == null) {
    return null;
  }
  return (
    name: _nameOf(link, link.host),
    client: XrayClientResult(
      clientId: 'imported',
      uuid: '',
      protocol: 'shadowsocks',
      password: password,
      method: method,
      serverAddress: link.host,
      port: port,
      sni: link.host,
      transport: 'raw',
      transportSecurity: 'none',
      adBlock: false,
    ),
  );
}

/// `hysteria2://auth@host:port/?sni=...&obfs=salamander&obfs-password=...`.
/// Port hopping (a range) and obfuscation other than Salamander are refused.
ImportedProfile? _parseHysteria2(String text) {
  final Uri? link = Uri.tryParse(text);
  if (link == null) {
    return null;
  }
  final String auth = Uri.decodeComponent(link.userInfo);
  final int? port = _port(link, text);
  final Map<String, String> query = link.queryParameters;
  final String obfs = (query['obfs'] ?? '').toLowerCase();
  final String obfsPassword = query['obfs-password'] ?? '';
  if (auth.isEmpty ||
      link.host.isEmpty ||
      port == null ||
      _insecure(query) ||
      query.containsKey('mport') ||
      (obfs.isNotEmpty && (obfs != 'salamander' || obfsPassword.isEmpty))) {
    return null;
  }
  final String sni = query['sni'] ?? query['peer'] ?? link.host;
  return (
    name: _nameOf(link, sni),
    client: XrayClientResult(
      clientId: 'imported',
      uuid: auth,
      serverAddress: link.host,
      port: port,
      sni: sni,
      transport: 'hysteria',
      transportSecurity: 'tls',
      adBlock: false,
      obfsPassword: obfs.isEmpty ? null : obfsPassword,
    ),
  );
}
