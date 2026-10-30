import 'dart:convert';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/network/api_exception.dart';
import 'package:nebula_mobile/core/servers/server_repository.dart';
import 'package:shared_preferences/shared_preferences.dart';

const Map<String, Object> _list = <String, Object>{
  'items': <Object>[
    <String, Object?>{
      'code': 'study-lab-1',
      'display_name': 'Example VPS',
      'public_host': 'api.example.test',
      'profiles': <Object>[
        <String, Object?>{
          'code': 'vless-ws-tls',
          'display_name': 'VLESS (WebSocket+TLS)',
          'protocol_id': 'p1',
          'protocol_code': 'vless',
          'ad_block': false,
          'required_port': 443,
          'requires_udp': false,
        },
      ],
    },
  ],
};

/// Answers with the list, or refuses the connection once [up] is false.
class _Server implements HttpClientAdapter {
  bool up = true;
  Map<String, dynamic> lastQuery = <String, dynamic>{};

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<Uint8List>? requestStream,
    Future<void>? cancelFuture,
  ) async {
    lastQuery = options.queryParameters;
    if (!up) {
      throw DioException(
        requestOptions: options,
        type: DioExceptionType.connectionError,
      );
    }
    return ResponseBody.fromString(
      jsonEncode(_list),
      200,
      headers: <String, List<String>>{
        Headers.contentTypeHeader: <String>['application/json'],
      },
    );
  }

  @override
  void close({bool force = false}) {}
}

Future<(DioServerRepository, _Server)> _repository() async {
  SharedPreferences.setMockInitialValues(<String, Object>{});
  final SharedPreferences preferences = await SharedPreferences.getInstance();
  final _Server server = _Server();
  final Dio dio = Dio(BaseOptions(baseUrl: 'https://api.example.test'))
    ..httpClientAdapter = server;
  return (DioServerRepository(dio, preferences: () => preferences), server);
}

void main() {
  test('an unreachable server gives back the last list it sent', () async {
    // Without it, Connect shows "Try again" instead of Connect, and the
    // saved tunnel credential -- the one thing that could still work --
    // can never be used.
    final (DioServerRepository repository, _Server server) =
        await _repository();
    await repository.listAvailableServers();

    server.up = false;
    final List<AvailableServer> servers = await repository
        .listAvailableServers();

    expect(servers.single.code, 'study-lab-1');
    expect(servers.single.profiles.single.code, 'vless-ws-tls');
  });

  test('with no earlier list, unreachable is still unreachable', () async {
    final (DioServerRepository repository, _Server server) =
        await _repository();
    server.up = false;

    await expectLater(
      repository.listAvailableServers(),
      throwsA(isA<NebulaConnectivityException>()),
    );
  });

  test('asks for servers under maintenance and reads the flag', () async {
    // An app that did not ask would not be sent them: one from before the
    // flag would list them as usable.
    final (DioServerRepository repository, _Server server) =
        await _repository();

    final List<AvailableServer> servers = await repository
        .listAvailableServers();

    expect(server.lastQuery['include_maintenance'], isTrue);
    expect(servers.single.maintenance, isFalse);
  });
}
