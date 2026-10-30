import 'dart:convert';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/network/api_route_sync.dart';
import 'package:nebula_mobile/core/network/route_fallback.dart';
import 'package:shared_preferences/shared_preferences.dart';

class _Answering implements HttpClientAdapter {
  _Answering(this.body);

  final Object? body;
  int calls = 0;

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<Uint8List>? requestStream,
    Future<void>? cancelFuture,
  ) async {
    calls++;
    if (body == null) {
      throw DioException(
        requestOptions: options,
        type: DioExceptionType.connectionError,
      );
    }
    return ResponseBody.fromString(
      jsonEncode(body),
      200,
      headers: <String, List<String>>{
        Headers.contentTypeHeader: <String>['application/json'],
      },
    );
  }

  @override
  void close({bool force = false}) {}
}

Future<(ApiRouteSync, SharedPreferences)> _sync(_Answering network) async {
  SharedPreferences.setMockInitialValues(<String, Object>{});
  final SharedPreferences preferences = await SharedPreferences.getInstance();
  final Dio dio = Dio(BaseOptions(baseUrl: 'https://direct.test'))
    ..httpClientAdapter = network;
  return (ApiRouteSync(dio, preferences), preferences);
}

void main() {
  test('keeps the addresses the server serves', () async {
    final (ApiRouteSync sync, SharedPreferences preferences) = await _sync(
      _Answering(<String, Object>{
        'routes': <String>['https://direct.test', 'https://cdn.test'],
      }),
    );

    await sync.refresh();

    expect(
      preferences.getString(kLearnedRoutesKey),
      jsonEncode(<String>['https://direct.test', 'https://cdn.test']),
    );
  });

  test('drops anything that is not an https address', () async {
    // The stored list is used to pick where credentials are sent next.
    final (ApiRouteSync sync, SharedPreferences preferences) = await _sync(
      _Answering(<String, Object>{
        'routes': <Object>['http://plain.test', 42, 'https://good.test'],
      }),
    );

    await sync.refresh();

    expect(
      preferences.getString(kLearnedRoutesKey),
      jsonEncode(<String>['https://good.test']),
    );
  });

  test('a server that cannot be reached leaves the list alone', () async {
    final (ApiRouteSync sync, SharedPreferences preferences) = await _sync(
      _Answering(null),
    );
    await preferences.setString(
      kLearnedRoutesKey,
      jsonEncode(<String>['https://kept.test']),
    );

    await sync.refresh();

    expect(
      preferences.getString(kLearnedRoutesKey),
      jsonEncode(<String>['https://kept.test']),
    );
  });

  test('an unexpected shape is ignored rather than stored', () async {
    final (ApiRouteSync sync, SharedPreferences preferences) = await _sync(
      _Answering(<String, Object>{'routes': 'not-a-list'}),
    );

    await sync.refresh();

    expect(preferences.getString(kLearnedRoutesKey), isNull);
  });
}
