import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../network/api_client.dart';
import '../network/api_exception.dart';

class AvailableProfile {
  const AvailableProfile({
    required this.code,
    required this.displayName,
    required this.protocolId,
  });

  final String code;
  final String displayName;
  final String protocolId;
}

class AvailableServer {
  const AvailableServer({
    required this.code,
    required this.displayName,
    required this.publicHost,
    required this.profiles,
  });

  final String code;
  final String displayName;
  final String publicHost;
  final List<AvailableProfile> profiles;
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

abstract interface class ServerRepository {
  Future<List<AvailableServer>> listAvailableServers();

  Future<WireGuardPeerResult> requestPeer({
    required String deviceId,
    required String serverCode,
    required String publicKey,
  });

  Future<void> revokePeer({
    required String deviceId,
    required String serverCode,
  });
}

class DioServerRepository implements ServerRepository {
  DioServerRepository(this._dio);

  final Dio _dio;

  @override
  Future<List<AvailableServer>> listAvailableServers() async {
    try {
      final Response<dynamic> response = await _dio.get<dynamic>(
        '/v1/servers/',
      );
      final Map<String, dynamic> data = response.data as Map<String, dynamic>;
      final List<dynamic> items = data['items'] as List<dynamic>;
      return items.map((dynamic rawItem) {
        final Map<String, dynamic> item = rawItem as Map<String, dynamic>;
        final List<dynamic> rawProfiles = item['profiles'] as List<dynamic>;
        return AvailableServer(
          code: item['code'] as String,
          displayName: item['display_name'] as String,
          publicHost: item['public_host'] as String,
          profiles: rawProfiles.map((dynamic rawProfile) {
            final Map<String, dynamic> profile =
                rawProfile as Map<String, dynamic>;
            return AvailableProfile(
              code: profile['code'] as String,
              displayName: profile['display_name'] as String,
              protocolId: profile['protocol_id'] as String,
            );
          }).toList(),
        );
      }).toList();
    } on DioException catch (error) {
      throw translateDioException(error);
    }
  }

  @override
  Future<WireGuardPeerResult> requestPeer({
    required String deviceId,
    required String serverCode,
    required String publicKey,
  }) async {
    try {
      final Response<dynamic> response = await _dio.post<dynamic>(
        '/v1/devices/$deviceId/wireguard-peer',
        data: <String, dynamic>{
          'server_code': serverCode,
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
}

final serverRepositoryProvider = Provider<ServerRepository>((Ref ref) {
  return DioServerRepository(ref.watch(dioProvider));
});
