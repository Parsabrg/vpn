import 'dart:convert';
import 'dart:io' show InternetAddress;

import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../free/free_mode.dart';
import '../network/api_client.dart';
import '../network/api_exception.dart';
import '../network/route_fallback.dart';
import '../settings/locale_controller.dart';
import '../storage/storage_providers.dart';

class AvailableProfile {
  const AvailableProfile({
    required this.code,
    required this.displayName,
    required this.protocolId,
    required this.protocolCode,
    required this.adBlock,
    this.requiredPort,
    this.requiresUdp = false,
  });

  final String code;
  final String displayName;
  final String protocolId;

  /// e.g. `"wireguard"` or `"vless"` -- [DevicesController] branches on this
  /// to pick which repository call and tunnel controller to use, since the
  /// two protocols have entirely different provisioning and tunnel-bringup
  /// paths.
  final String protocolCode;

  /// True for a profile's ad-blocking sibling (e.g. "VLESS XHTTP (Ad-block)"
  /// next to plain "VLESS XHTTP") -- a separate, manually-selectable picker
  /// entry, not a toggle.
  final bool adBlock;

  /// Where this profile is reached, so a server can be measured before it is
  /// chosen. Nullable: a profile without one is not broken, it is one that
  /// cannot be measured.
  final int? requiredPort;

  /// Hysteria2 and WireGuard. A UDP socket accepts a connect() and sends
  /// into the void whether or not anything is listening, so these are
  /// reported unmeasured rather than fast.
  final bool requiresUdp;

  /// The direct, self-encrypted profiles (Shadowsocks-2022, VLESS
  /// Encryption, VMess). Automatic leaves them out: they pass a quick check,
  /// but a browser's traffic over them was cut about 2.5 KB into each
  /// connection on a home line in Iran (Chrome on the phone, 2026-10-23),
  /// so a page hung while the app said Protected. Still there to pick by
  /// hand.
  bool get manualOnly =>
      protocolCode == 'shadowsocks' ||
      protocolCode == 'vmess' ||
      code.startsWith('vless-enc');
}

class AvailableServer {
  const AvailableServer({
    required this.code,
    required this.displayName,
    required this.publicHost,
    required this.profiles,
    this.maintenance = false,
  });

  final String code;
  final String displayName;
  final String publicHost;
  final List<AvailableProfile> profiles;

  /// Listed so the person can see why it cannot be used, rather than have it
  /// vanish. Takes no new connections until it is active again.
  final bool maintenance;
}

/// The full WireGuard client configuration payload -- this response is the
/// entirety of it; there is no separate profile-fetch endpoint, so the
/// caller must persist whatever it needs from this.
class WireGuardPeerResult {
  const WireGuardPeerResult({
    required this.peerId,
    required this.assignedAddress,
    required this.serverPublicKey,
    required this.listenPort,
    required this.publicEndpoint,
    required this.clientDns,
    required this.clientAllowedIps,
    required this.persistentKeepaliveSeconds,
  });

  final String peerId;
  final String assignedAddress;
  final String serverPublicKey;
  final int listenPort;
  final String publicEndpoint;
  final String clientDns;
  final String clientAllowedIps;
  final int persistentKeepaliveSeconds;
}

/// The full Xray client configuration payload -- mirrors [WireGuardPeerResult]'s
/// shape: this response is the entirety of what the caller needs to both
/// render a client config and display connection details, across every
/// transport (XHTTP, gRPC, WebSocket, raw TCP, Hysteria2).
class XrayClientResult {
  const XrayClientResult({
    required this.clientId,
    required this.uuid,
    required this.serverAddress,
    required this.port,
    required this.sni,
    required this.transport,
    required this.transportSecurity,
    required this.adBlock,
    this.path,
    this.serviceName,
    this.obfsPassword,
    this.clientDns = const <String>[],
    this.caCertificate,
    this.echConfigList,
    this.protocol = 'vless',
    this.password,
    this.method,
    this.encryption,
    this.flow,
    this.realityPublicKey,
    this.realityShortId,
    this.fingerprint,
  });

  /// `vless` (most Nebula profiles), `shadowsocks` or `vmess` (the direct
  /// profiles), or `trojan` from a link. Hysteria2 is told by [transport].
  final String protocol;

  /// Trojan's or Shadowsocks' secret, where VLESS has [uuid].
  final String? password;

  /// The Shadowsocks cipher, as Xray names it.
  final String? method;

  /// VLESS Encryption's client string (`mlkem768x25519plus...`); `none`
  /// when null, as for every other VLESS profile.
  final String? encryption;

  /// VLESS flow: `xtls-rprx-vision`, or null.
  final String? flow;

  /// REALITY's server key and short id; set only when [transportSecurity]
  /// is `reality`.
  final String? realityPublicKey;
  final String? realityShortId;

  /// The TLS fingerprint a link asks for; Chrome's when null.
  final String? fingerprint;

  final String clientId;
  final String uuid;
  final String serverAddress;
  final int port;
  final String sni;

  /// `"xhttp"`, `"grpc"`, `"websocket"`, `"raw"`, or `"hysteria"` -- picks
  /// which `streamSettings` shape [renderXrayClientConfigJson] builds.
  final String transport;
  final String transportSecurity;

  /// Set only for xhttp/websocket -- the shared path every client on that
  /// inbound uses.
  final String? path;

  /// Set only for grpc -- the shared service name every client on that
  /// inbound uses.
  final String? serviceName;

  /// Set only for hysteria -- the Salamander obfuscation password
  /// [renderXrayClientConfigJson] needs to render a matching `udpmasks`
  /// block, without which plain QUIC/Hysteria2 handshakes get fingerprinted
  /// and silently dropped by some ISPs (confirmed live).
  final String? obfsPassword;

  /// True when the connected profile was an ad-blocking sibling --
  /// [renderXrayClientConfigJson] uses this to decide whether to add a
  /// `dns` module to the client config it renders locally.
  final bool adBlock;

  /// The resolvers the deployment gives its clients, chosen by its operator
  /// at install. Empty from a server that predates it.
  final List<String> clientDns;

  /// The installation's own CA (PEM), when its TLS certificate is one it
  /// issued itself -- an install reached by IP address. The tunnel's TLS is
  /// verified against it, as the API's is. Null for a publicly trusted
  /// certificate, and for the CDN route.
  final String? caCertificate;

  /// Xray's `echConfigList` (Encrypted Client Hello), when the server says
  /// the tunnel goes through Cloudflare. See [echConfigListFor].
  final String? echConfigList;
}

/// The resolver list a server sent, keeping IP addresses only: these go into
/// a tunnel config and a Windows helper's arguments, where a hostname would
/// need a lookup through the network the tunnel is there to avoid.
List<String> clientDnsFrom(Object? value) => <String>[
  if (value is List<Object?>)
    for (final Object? entry in value)
      if (entry is String && InternetAddress.tryParse(entry) != null) entry,
];

abstract interface class ServerRepository {
  Future<List<AvailableServer>> listAvailableServers();

  Future<WireGuardPeerResult> requestPeer({
    required String deviceId,
    required String serverCode,
    required String protocolProfileCode,
    required String publicKey,
  });

  Future<void> revokePeer({
    required String deviceId,
    required String serverCode,
  });

  Future<XrayClientResult> requestXrayClient({
    required String deviceId,
    required String serverCode,
    required String protocolProfileCode,
  });

  Future<void> revokeXrayClient({
    required String deviceId,
    required String serverCode,
    required String protocolProfileCode,
  });
}

class DioServerRepository implements ServerRepository {
  DioServerRepository(this._dio, {this.preferences});

  final Dio _dio;

  /// Where the last list the server sent is kept, read lazily. Absent means
  /// no copy is kept, which is what tests that do not care get.
  final SharedPreferences? Function()? preferences;

  static const String cachedListKey = 'nebula.servers_cache';

  /// The server list, or the last one the server sent when it cannot be
  /// reached.
  ///
  /// Without the copy, a phone that cannot reach the API has no list, so the
  /// Connect screen offers "Try again" instead of Connect -- and the saved
  /// credential for the tunnel, the one thing that could still work, can
  /// never be used. The list is not secret: server names, profile names and
  /// the ports a client dials, all of which the server hands every signed-in
  /// client anyway.
  @override
  Future<List<AvailableServer>> listAvailableServers() async {
    try {
      final Response<dynamic> response = await _dio.get<dynamic>(
        '/v1/servers/',
        // Asked for, because an app from before the flag would list these
        // as usable and fail to connect.
        queryParameters: <String, dynamic>{'include_maintenance': true},
      );
      final Map<String, dynamic> data = response.data as Map<String, dynamic>;
      final List<AvailableServer> servers = _parseServers(data);
      try {
        await preferences?.call()?.setString(cachedListKey, jsonEncode(data));
      } catch (_) {
        // A copy that could not be kept only matters on a later failure.
      }
      return servers;
    } on DioException catch (error) {
      final Object translated = translateDioException(error);
      if (translated is NebulaConnectivityException) {
        final List<AvailableServer>? cached = _cachedServers();
        if (cached != null) {
          return cached;
        }
      }
      throw translated;
    }
  }

  List<AvailableServer>? _cachedServers() {
    try {
      final String? stored = preferences?.call()?.getString(cachedListKey);
      if (stored == null) {
        return null;
      }
      return _parseServers(jsonDecode(stored) as Map<String, dynamic>);
    } catch (_) {
      // Unreadable or from an older shape: no list is the honest answer.
      return null;
    }
  }

  static List<AvailableServer> _parseServers(Map<String, dynamic> data) {
    final List<dynamic> items = data['items'] as List<dynamic>;
    return items.map((dynamic rawItem) {
      final Map<String, dynamic> item = rawItem as Map<String, dynamic>;
      final List<dynamic> rawProfiles = item['profiles'] as List<dynamic>;
      return AvailableServer(
        code: item['code'] as String,
        displayName: item['display_name'] as String,
        publicHost: item['public_host'] as String,
        maintenance: (item['maintenance'] as bool?) ?? false,
        profiles: rawProfiles.cast<Map<String, dynamic>>().map((
          Map<String, dynamic> profile,
        ) {
          return AvailableProfile(
            code: profile['code'] as String,
            displayName: profile['display_name'] as String,
            protocolId: profile['protocol_id'] as String,
            protocolCode: profile['protocol_code'] as String,
            adBlock: profile['ad_block'] as bool,
            requiredPort: profile['required_port'] as int?,
            requiresUdp: (profile['requires_udp'] as bool?) ?? false,
          );
        }).toList(),
      );
    }).toList();
  }

  @override
  Future<WireGuardPeerResult> requestPeer({
    required String deviceId,
    required String serverCode,
    required String protocolProfileCode,
    required String publicKey,
  }) async {
    try {
      final Response<dynamic> response = await _dio.post<dynamic>(
        '/v1/devices/$deviceId/wireguard-peer',
        data: <String, dynamic>{
          'server_code': serverCode,
          'protocol_profile_code': protocolProfileCode,
          'public_key': publicKey,
        },
      );
      final Map<String, dynamic> data = response.data as Map<String, dynamic>;
      return WireGuardPeerResult(
        peerId: data['peer_id'] as String,
        assignedAddress: data['assigned_address'] as String,
        serverPublicKey: data['server_public_key'] as String,
        listenPort: data['listen_port'] as int,
        publicEndpoint: data['public_endpoint'] as String,
        clientDns: data['client_dns'] as String,
        clientAllowedIps: data['client_allowed_ips'] as String,
        persistentKeepaliveSeconds: data['persistent_keepalive_seconds'] as int,
      );
    } on DioException catch (error) {
      throw translateDioException(error);
    }
  }

  @override
  Future<void> revokePeer({
    required String deviceId,
    required String serverCode,
  }) async {
    try {
      await _dio.post<dynamic>(
        '/v1/devices/$deviceId/wireguard-peer/revoke',
        data: <String, dynamic>{'server_code': serverCode},
      );
    } on DioException catch (error) {
      throw translateDioException(error);
    }
  }

  @override
  Future<XrayClientResult> requestXrayClient({
    required String deviceId,
    required String serverCode,
    required String protocolProfileCode,
  }) async {
    try {
      final Response<dynamic> response = await _dio.post<dynamic>(
        '/v1/devices/$deviceId/xray-client',
        data: <String, dynamic>{
          'server_code': serverCode,
          'protocol_profile_code': protocolProfileCode,
        },
        // The server hands back the credential this device already holds,
        // so asking again over another route changes nothing.
        options: Options(extra: <String, dynamic>{kRepeatable: true}),
      );
      final Map<String, dynamic> data = response.data as Map<String, dynamic>;
      return XrayClientResult(
        clientId: data['client_id'] as String,
        uuid: data['uuid'] as String,
        serverAddress: data['server_address'] as String,
        port: data['port'] as int,
        sni: data['sni'] as String,
        transport: data['transport'] as String,
        transportSecurity: data['transport_security'] as String,
        adBlock: data['ad_block'] as bool,
        path: data['path'] as String?,
        serviceName: data['service_name'] as String?,
        obfsPassword: data['obfs_password'] as String?,
        // Shadowsocks-2022 (roadmap: direct route Iran lets through); an
        // older server sends none of these and means VLESS.
        protocol: data['protocol'] as String? ?? 'vless',
        method: data['method'] as String?,
        password: data['password'] as String?,
        encryption: data['encryption'] as String?,
        echConfigList: data['ech_config_list'] as String?,
        clientDns: clientDnsFrom(data['client_dns']),
        caCertificate: data['ca_certificate'] as String?,
      );
    } on DioException catch (error) {
      throw translateDioException(error);
    }
  }

  @override
  Future<void> revokeXrayClient({
    required String deviceId,
    required String serverCode,
    required String protocolProfileCode,
  }) async {
    try {
      await _dio.post<dynamic>(
        '/v1/devices/$deviceId/xray-client/revoke',
        data: <String, dynamic>{
          'server_code': serverCode,
          'protocol_profile_code': protocolProfileCode,
        },
      );
    } on DioException catch (error) {
      throw translateDioException(error);
    }
  }
}

final serverRepositoryProvider = Provider<ServerRepository>((Ref ref) {
  // With no server, the list and the credentials are this device's own.
  if (ref.watch(freeModeProvider)) {
    return LocalServerRepository(
      builtIn: ref.watch(builtInFreeLinksProvider),
      store: ref.watch(freeLinkStoreProvider),
      subscriptions: ref.watch(subscriptionStoreProvider),
      importedName: () => ref.read(appTextProvider).ownLinksImported,
      builtInName: () => ref.read(appTextProvider).freeBuiltInGroup,
    );
  }
  // Signed in: the server's list, then the links and subscriptions added on
  // this device. The build's shared relays are for using the app without a
  // server, and stay out of it.
  return CombinedServerRepository(
    server: DioServerRepository(
      ref.watch(dioProvider),
      preferences: () => ref.read(sharedPreferencesProvider),
    ),
    own: LocalServerRepository(
      builtIn: const <String>[],
      store: ref.watch(freeLinkStoreProvider),
      subscriptions: ref.watch(subscriptionStoreProvider),
      // Asked when the list is built, in the language of the moment.
      importedName: () => ref.read(appTextProvider).ownLinksImported,
    ),
  );
});
