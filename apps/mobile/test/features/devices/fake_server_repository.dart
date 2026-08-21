import 'package:nebula_mobile/core/servers/server_repository.dart';

class FakeServerRepository implements ServerRepository {
  List<AvailableServer> servers = <AvailableServer>[];
  Object? listError;

  WireGuardPeerResult? requestPeerResult;
  Object? requestPeerError;
  int requestPeerCalls = 0;
  String? lastRequestedServerCode;
  String? lastRequestedPublicKey;

  int revokePeerCalls = 0;
  String? lastRevokedServerCode;
  Object? revokePeerError;

  @override
  Future<List<AvailableServer>> listAvailableServers() async {
    final Object? error = listError;
    if (error != null) {
      throw error;
    }
    return servers;
  }

  @override
  Future<WireGuardPeerResult> requestPeer({
    required String deviceId,
    required String serverCode,
    required String publicKey,
  }) async {
    requestPeerCalls++;
    lastRequestedServerCode = serverCode;
    lastRequestedPublicKey = publicKey;
    final Object? error = requestPeerError;
    if (error != null) {
      throw error;
    }
    return requestPeerResult!;
  }

  @override
  Future<void> revokePeer({
    required String deviceId,
    required String serverCode,
  }) async {
    revokePeerCalls++;
    lastRevokedServerCode = serverCode;
    final Object? error = revokePeerError;
    if (error != null) {
      throw error;
    }
  }
}
