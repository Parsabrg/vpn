import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import '../servers/server_repository.dart';
import '../tunnel/tunnel_traffic.dart';
import '../xray/local_proxy.dart';

/// The connection a running tunnel was built from, kept so a later run of the
/// app can pick the tunnel back up.
///
/// A tunnel outlives the screen that started it. Without this, reopening the
/// app while connected showed "Off" over a working VPN, and Disconnect had
/// nothing on record to revoke. With it, the app shows the connection that is
/// actually up and can take it down properly.
///
/// Written only once a tunnel has come up, and removed when it is taken down,
/// so a record that exists describes the last tunnel this app started. It is
/// only ever acted on while Android reports this app's VPN as up.
class ConnectionRecord {
  const ConnectionRecord({
    required this.serverCode,
    required this.profileCode,
    required this.protocolCode,
    required this.sanctionsOnly,
    this.peer,
    this.xrayClient,
    this.localProxyPort,
    this.tunnelProxy,
    this.establishedAt,
    this.trafficBaseline,
  });

  final String serverCode;
  final String profileCode;
  final String protocolCode;
  final bool sanctionsOnly;
  final WireGuardPeerResult? peer;
  final XrayClientResult? xrayClient;

  /// Set when the connection runs as a local proxy rather than a VPN: the
  /// port a later run looks at to tell whether it is still up.
  final int? localProxyPort;

  /// The VPN's own proxy, between tun2socks and the engine. Kept so a
  /// reopened app can still ask a request through the tunnel: this app is
  /// excluded from its own VPN, so a plain request from it proves only that
  /// the phone is online, and the traffic watch said "working" over a tunnel
  /// that carried nothing for as long as the reopened app ran.
  final LocalProxy? tunnelProxy;

  /// When the tunnel came up. Kept so the session's clock survives the app's
  /// screen being closed and reopened while the tunnel runs on: a reopened
  /// app used to show no session time at all, which read as the connection
  /// having started over. Null in a record written before this existed.
  final DateTime? establishedAt;

  /// The engine's byte counters when the session began, so the figures
  /// shown after a reopen continue rather than restarting from zero.
  /// Written once the first reading arrives.
  final TunnelTraffic? trafficBaseline;

  ConnectionRecord withTrafficBaseline(TunnelTraffic baseline) {
    return ConnectionRecord(
      serverCode: serverCode,
      profileCode: profileCode,
      protocolCode: protocolCode,
      sanctionsOnly: sanctionsOnly,
      peer: peer,
      xrayClient: xrayClient,
      localProxyPort: localProxyPort,
      tunnelProxy: tunnelProxy,
      establishedAt: establishedAt,
      trafficBaseline: TunnelTraffic(
        rxBytes: baseline.rxBytes,
        txBytes: baseline.txBytes,
      ),
    );
  }

  Map<String, Object?> toJson() => <String, Object?>{
    'serverCode': serverCode,
    'profileCode': profileCode,
    'protocolCode': protocolCode,
    'sanctionsOnly': sanctionsOnly,
    if (localProxyPort case final int port) 'localProxyPort': port,
    if (tunnelProxy case final LocalProxy proxy) ...<String, Object?>{
      'tunnelProxyPort': proxy.port,
      'tunnelProxyUsername': proxy.username,
      'tunnelProxyPassword': proxy.password,
    },
    if (establishedAt case final DateTime at)
      'establishedAtMs': at.millisecondsSinceEpoch,
    if (trafficBaseline case final TunnelTraffic baseline) ...<String, Object?>{
      'baselineRxBytes': baseline.rxBytes,
      'baselineTxBytes': baseline.txBytes,
    },
    if (peer case final WireGuardPeerResult peer)
      'peer': <String, Object?>{
        'peerId': peer.peerId,
        'assignedAddress': peer.assignedAddress,
        'serverPublicKey': peer.serverPublicKey,
        'listenPort': peer.listenPort,
        'publicEndpoint': peer.publicEndpoint,
        'clientDns': peer.clientDns,
        'clientAllowedIps': peer.clientAllowedIps,
        'persistentKeepaliveSeconds': peer.persistentKeepaliveSeconds,
      },
    if (xrayClient case final XrayClientResult client)
      'xrayClient': <String, Object?>{
        'clientId': client.clientId,
        'uuid': client.uuid,
        'serverAddress': client.serverAddress,
        'port': client.port,
        'sni': client.sni,
        'transport': client.transport,
        'transportSecurity': client.transportSecurity,
        'adBlock': client.adBlock,
        'path': client.path,
        'serviceName': client.serviceName,
        'obfsPassword': client.obfsPassword,
        'clientDns': client.clientDns,
        'protocol': client.protocol,
        'password': client.password,
        'method': client.method,
        'encryption': client.encryption,
        'flow': client.flow,
        'realityPublicKey': client.realityPublicKey,
        'realityShortId': client.realityShortId,
        'fingerprint': client.fingerprint,
        'echConfigList': client.echConfigList,
      },
  };

  /// Null for anything that is not a complete record, including one written
  /// by a version of the app with a different shape: a record that cannot be
  /// trusted is treated as no record, never as a partial connection.
  static ConnectionRecord? fromJson(Object? json) {
    try {
      final Map<String, Object?> map = (json! as Map<Object?, Object?>)
          .cast<String, Object?>();
      final Object? peer = map['peer'];
      final Object? client = map['xrayClient'];
      if ((peer == null) == (client == null)) {
        return null; // Exactly one engine ran a tunnel.
      }
      return ConnectionRecord(
        serverCode: map['serverCode']! as String,
        profileCode: map['profileCode']! as String,
        protocolCode: map['protocolCode']! as String,
        sanctionsOnly: map['sanctionsOnly']! as bool,
        localProxyPort: map['localProxyPort'] as int?,
        tunnelProxy: switch ((
          map['tunnelProxyPort'],
          map['tunnelProxyUsername'],
          map['tunnelProxyPassword'],
        )) {
          (final int port, final String username, final String password) =>
            LocalProxy(port: port, username: username, password: password),
          _ => null,
        },
        establishedAt: switch (map['establishedAtMs']) {
          final int millis => DateTime.fromMillisecondsSinceEpoch(millis),
          _ => null,
        },
        trafficBaseline: switch ((
          map['baselineRxBytes'],
          map['baselineTxBytes'],
        )) {
          (final int rx, final int tx) => TunnelTraffic(
            rxBytes: rx,
            txBytes: tx,
          ),
          _ => null,
        },
        peer: peer == null ? null : _peerFrom(peer as Map<Object?, Object?>),
        xrayClient: client == null
            ? null
            : _clientFrom(client as Map<Object?, Object?>),
      );
    } on Object {
      return null;
    }
  }

  static WireGuardPeerResult _peerFrom(Map<Object?, Object?> map) {
    return WireGuardPeerResult(
      peerId: map['peerId']! as String,
      assignedAddress: map['assignedAddress']! as String,
      serverPublicKey: map['serverPublicKey']! as String,
      listenPort: map['listenPort']! as int,
      publicEndpoint: map['publicEndpoint']! as String,
      clientDns: map['clientDns']! as String,
      clientAllowedIps: map['clientAllowedIps']! as String,
      persistentKeepaliveSeconds: map['persistentKeepaliveSeconds']! as int,
    );
  }

  static XrayClientResult _clientFrom(Map<Object?, Object?> map) {
    return XrayClientResult(
      clientId: map['clientId']! as String,
      uuid: map['uuid']! as String,
      serverAddress: map['serverAddress']! as String,
      port: map['port']! as int,
      sni: map['sni']! as String,
      transport: map['transport']! as String,
      transportSecurity: map['transportSecurity']! as String,
      adBlock: map['adBlock']! as bool,
      path: map['path'] as String?,
      serviceName: map['serviceName'] as String?,
      obfsPassword: map['obfsPassword'] as String?,
      clientDns: clientDnsFrom(map['clientDns']),
      echConfigList: map['echConfigList'] as String?,
      protocol: map['protocol'] as String? ?? 'vless',
      password: map['password'] as String?,
      method: map['method'] as String?,
      encryption: map['encryption'] as String?,
      flow: map['flow'] as String?,
      realityPublicKey: map['realityPublicKey'] as String?,
      realityShortId: map['realityShortId'] as String?,
      fingerprint: map['fingerprint'] as String?,
    );
  }
}

abstract interface class ConnectionRecordStore {
  Future<ConnectionRecord?> read();
  Future<void> write(ConnectionRecord record);
  Future<void> clear();
}

/// In secure storage, beside the WireGuard key: an Xray record carries the
/// client's UUID and a Hysteria2 one its obfuscation password, and either is
/// enough to use the server.
class SecureConnectionRecordStore implements ConnectionRecordStore {
  SecureConnectionRecordStore({FlutterSecureStorage? storage})
    : _storage = storage ?? const FlutterSecureStorage();

  static const String _key = 'nebula.active_connection';

  final FlutterSecureStorage _storage;

  @override
  Future<ConnectionRecord?> read() async {
    final String? raw = await _storage.read(key: _key);
    if (raw == null) {
      return null;
    }
    try {
      return ConnectionRecord.fromJson(jsonDecode(raw));
    } on FormatException {
      return null;
    }
  }

  @override
  Future<void> write(ConnectionRecord record) =>
      _storage.write(key: _key, value: jsonEncode(record.toJson()));

  @override
  Future<void> clear() => _storage.delete(key: _key);
}

/// In-memory fake for tests. Round-trips through JSON, so a field the record
/// forgets to write fails here rather than on a phone.
class InMemoryConnectionRecordStore implements ConnectionRecordStore {
  String? _raw;

  @override
  Future<ConnectionRecord?> read() async {
    final String? raw = _raw;
    return raw == null ? null : ConnectionRecord.fromJson(jsonDecode(raw));
  }

  @override
  Future<void> write(ConnectionRecord record) async {
    _raw = jsonEncode(record.toJson());
  }

  @override
  Future<void> clear() async {
    _raw = null;
  }
}
