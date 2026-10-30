import 'dart:convert';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/auth/token_pair.dart';
import 'package:nebula_mobile/core/network/api_exception.dart';
import 'package:nebula_mobile/core/network/auth_interceptor.dart';

/// Answers every request with [status], counting them.
class _Always implements HttpClientAdapter {
  _Always(this.status);

  final int status;
  final List<RequestOptions> requests = <RequestOptions>[];

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<Uint8List>? requestStream,
    Future<void>? cancelFuture,
  ) async {
    requests.add(options);
    return ResponseBody.fromString(
      jsonEncode(<String, String>{'detail': 'x'}),
      status,
      headers: <String, List<String>>{
        Headers.contentTypeHeader: <String>['application/json'],
      },
    );
  }

  @override
  void close({bool force = false}) {}
}

({Dio dio, _Always adapter, List<int> refreshes}) _client(int status) {
  final _Always adapter = _Always(status);
  final List<int> refreshes = <int>[];
  final Dio dio = Dio(BaseOptions(baseUrl: 'https://api.example.test'))
    ..httpClientAdapter = adapter;
  dio.interceptors.add(
    AuthInterceptor.withDependencies(
      accessToken: () => 'expired',
      refresh: () async {
        refreshes.add(1);
        return const TokenPair(
          accessToken: 'fresh',
          refreshToken: 'r',
          expiresIn: Duration(minutes: 15),
        );
      },
      fetch: (RequestOptions options) => dio.fetch<dynamic>(options),
    ),
  );
  return (dio: dio, adapter: adapter, refreshes: refreshes);
}

void main() {
  test('a request that is refused again after refreshing is not retried '
      'again', () async {
    // Found in the field: a session revoked between refresh and retry made
    // the retried request 401, which refreshed and retried, without end.
    final client = _client(401);

    await expectLater(
      client.dio.get<dynamic>('/v1/servers/'),
      throwsA(
        isA<DioException>().having(
          (DioException e) => e.response?.statusCode,
          'status',
          401,
        ),
      ),
    );

    expect(client.refreshes, hasLength(1));
    expect(client.adapter.requests, hasLength(2));
    expect(
      client.adapter.requests.last.headers['Authorization'],
      'Bearer fresh',
    );
  });

  test('an unauthenticated path is never refreshed', () async {
    final client = _client(401);

    await expectLater(
      client.dio.post<dynamic>('/v1/auth/login', data: <String, String>{}),
      throwsA(isA<DioException>()),
    );

    expect(client.refreshes, isEmpty);
    expect(client.adapter.requests, hasLength(1));
  });

  test('a success needs no refresh', () async {
    final client = _client(200);

    await client.dio.get<dynamic>('/v1/servers/');

    expect(client.refreshes, isEmpty);
    expect(
      client.adapter.requests.single.headers['Authorization'],
      'Bearer expired',
    );
  });

  test('a refresh that cannot reach the server is a connection failure, '
      'not a refused sign-in', () async {
    final _Always adapter = _Always(401);
    final Dio dio = Dio(BaseOptions(baseUrl: 'https://api.example.test'))
      ..httpClientAdapter = adapter;
    dio.interceptors.add(
      AuthInterceptor.withDependencies(
        accessToken: () => 'expired',
        refresh: () async =>
            throw const NebulaConnectivityException('timed out'),
        fetch: (RequestOptions options) => dio.fetch<dynamic>(options),
      ),
    );

    await expectLater(
      dio.get<dynamic>('/v1/servers/'),
      throwsA(
        isA<DioException>().having(
          (DioException e) => e.type,
          'type',
          DioExceptionType.connectionError,
        ),
      ),
    );
  });
}
