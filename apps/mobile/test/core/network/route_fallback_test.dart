import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/network/route_fallback.dart';
import 'package:shared_preferences/shared_preferences.dart';

const String _direct = 'https://direct.test';
const String _backup = 'https://backup.test';

/// Answers on the hosts in [up]; every other host refuses the connection the
/// way a blocked address does, or fails as [failure] says.
class _Network implements HttpClientAdapter {
  _Network(
    this.up, {
    this.failure = DioExceptionType.connectionError,
    this.stalled = const <String>{},
    this.refusals = const <String, (int, String, String)>{},
  });

  Set<String> up;
  final DioExceptionType failure;

  /// Hosts that answer with (status, content type, body) instead.
  final Map<String, (int, String, String)> refusals;

  /// Hosts that accept the request and never answer, like a throttled one.
  final Set<String> stalled;
  final List<String> hosts = <String>[];

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<Uint8List>? requestStream,
    Future<void>? cancelFuture,
  ) async {
    hosts.add(options.uri.host);
    if (stalled.contains(options.uri.host)) {
      await cancelFuture;
      throw DioException.requestCancelled(
        requestOptions: options,
        reason: 'lost the race',
      );
    }
    final (int, String, String)? refusal = refusals[options.uri.host];
    if (refusal != null) {
      final (int status, String type, String body) = refusal;
      return ResponseBody.fromString(
        body,
        status,
        headers: <String, List<String>>{
          Headers.contentTypeHeader: <String>[type],
        },
      );
    }
    if (!up.contains(options.uri.host)) {
      throw DioException(requestOptions: options, type: failure);
    }
    return ResponseBody.fromString(
      jsonEncode(<String, String>{'via': options.uri.host}),
      200,
      headers: <String, List<String>>{
        Headers.contentTypeHeader: <String>['application/json'],
      },
    );
  }

  @override
  void close({bool force = false}) {}
}

Future<(Dio, _Network, SharedPreferences)> _client(
  Set<String> up, {
  Map<String, Object> stored = const <String, Object>{},
  DioExceptionType failure = DioExceptionType.connectionError,
  Set<String> stalled = const <String>{},
  Map<String, (int, String, String)> refusals =
      const <String, (int, String, String)>{},
}) async {
  SharedPreferences.setMockInitialValues(stored);
  final SharedPreferences preferences = await SharedPreferences.getInstance();
  final _Network network = _Network(
    up,
    failure: failure,
    stalled: stalled,
    refusals: refusals,
  );
  final Dio dio = Dio(BaseOptions(baseUrl: _direct))
    ..httpClientAdapter = network;
  dio.interceptors.add(
    RouteFallbackInterceptor(
      dio: dio,
      routes: <String>[_direct, _backup],
      preferences: () => preferences,
      hedgeAfter: const Duration(milliseconds: 50),
    ),
  );
  return (dio, network, preferences);
}

void main() {
  test('a blocked direct address falls over to the backup', () async {
    final (Dio dio, _Network network, _) = await _client(<String>{
      'backup.test',
    });

    final Response<dynamic> response = await dio.get<dynamic>('/v1/me');

    expect(response.data, <String, String>{'via': 'backup.test'});
    expect(network.hosts, <String>['direct.test', 'backup.test']);
  });

  test('once the backup works, it is used first -- across launches', () async {
    final (Dio dio, _Network network, SharedPreferences preferences) =
        await _client(<String>{'backup.test'});
    await dio.get<dynamic>('/v1/me');
    network.hosts.clear();

    await dio.get<dynamic>('/v1/servers/');
    expect(network.hosts, <String>['backup.test']);

    // A new launch reads the remembered route rather than paying the
    // connect timeout on the blocked address again.
    final (Dio relaunched, _Network again, _) = await _client(
      <String>{'backup.test'},
      stored: <String, Object>{
        kRememberedRouteKey: preferences.getString(kRememberedRouteKey)!,
        kRememberedRouteAtKey: preferences.getInt(kRememberedRouteAtKey)!,
      },
    );
    await relaunched.get<dynamic>('/v1/me');
    expect(again.hosts, <String>['backup.test']);
  });

  test('a fallback remembered over an hour ago gives way to the first '
      'address again', () async {
    // The first address may be back: a throttled one swapped for a new one.
    final (Dio dio, _Network network, _) = await _client(
      <String>{'direct.test', 'backup.test'},
      stored: <String, Object>{
        kRememberedRouteKey: _backup,
        kRememberedRouteAtKey: DateTime.now()
            .subtract(const Duration(hours: 2))
            .millisecondsSinceEpoch,
      },
    );

    await dio.get<dynamic>('/v1/me');

    expect(network.hosts, <String>['direct.test']);
  });

  test('an address learned from the server is tried too', () async {
    // The point of learning them: this address did not exist when the app
    // was built, and reaching it needs no new build.
    const String learned = 'https://learned.test';
    final (Dio dio, _Network network, _) = await _client(
      <String>{'learned.test'},
      stored: <String, Object>{
        kLearnedRoutesKey: jsonEncode(<String>[learned]),
      },
    );

    final Response<dynamic> response = await dio.get<dynamic>('/v1/me');

    expect(response.data, <String, String>{'via': 'learned.test'});
    expect(network.hosts, <String>[
      'direct.test',
      'backup.test',
      'learned.test',
    ]);
  });

  test('a learned address that is not https is ignored', () async {
    final (Dio dio, _Network network, _) = await _client(
      <String>{'backup.test'},
      stored: <String, Object>{
        kLearnedRoutesKey: jsonEncode(<String>['http://plain.test']),
      },
    );

    await dio.get<dynamic>('/v1/me');

    expect(network.hosts, <String>['direct.test', 'backup.test']);
  });

  const (int, String, String) disabledFront = (
    402,
    'text/plain; charset=utf-8',
    'Payment required\n\nDEPLOYMENT_DISABLED\n',
  );

  test('a front that refuses in its own words is a dead route', () async {
    // A disabled Vercel front answered every request with this 402, and the
    // app showed "Data limit reached" while the API worked on every other
    // route (2026-10-29).
    final (Dio dio, _Network network, _) = await _client(
      <String>{'backup.test'},
      refusals: <String, (int, String, String)>{'direct.test': disabledFront},
    );

    final Response<dynamic> response = await dio.get<dynamic>('/v1/me');

    expect(response.data, <String, String>{'via': 'backup.test'});
    expect(network.hosts, <String>['direct.test', 'backup.test']);
  });

  test('the API\'s own refusal is the answer, not a dead route', () async {
    final (Dio dio, _Network network, _) = await _client(
      <String>{'backup.test'},
      refusals: <String, (int, String, String)>{
        'direct.test': (
          402,
          'application/json',
          '{"detail":"The traffic allowance is used up"}',
        ),
      },
    );

    await expectLater(
      dio.get<dynamic>('/v1/me'),
      throwsA(
        isA<DioException>().having(
          (DioException e) => e.response?.statusCode,
          'status',
          402,
        ),
      ),
    );
    expect(network.hosts, <String>['direct.test']);
  });

  test('a POST a front refused moves on: it never reached the API', () async {
    final (Dio dio, _Network network, _) = await _client(
      <String>{'backup.test'},
      refusals: <String, (int, String, String)>{'direct.test': disabledFront},
    );

    final Response<dynamic> response = await dio.post<dynamic>(
      '/v1/auth/login',
    );

    expect((response.data as Map<String, dynamic>)['via'], 'backup.test');
  });

  test('moves back to the direct address when the backup fails', () async {
    final (Dio dio, _Network network, _) = await _client(
      <String>{'direct.test'},
      stored: <String, Object>{
        kRememberedRouteKey: _backup,
        kRememberedRouteAtKey: DateTime.now().millisecondsSinceEpoch,
      },
    );

    final Response<dynamic> response = await dio.get<dynamic>('/v1/me');

    expect(response.data, <String, String>{'via': 'direct.test'});
    expect(network.hosts, <String>['backup.test', 'direct.test']);
  });

  test(
    'a response timeout is not retried: the request may have landed',
    () async {
      // A sign-in that timed out waiting for its answer may already have been
      // counted; sending it again elsewhere is not safe.
      final (Dio dio, _Network network, _) = await _client(<String>{
        'backup.test',
      }, failure: DioExceptionType.receiveTimeout);

      await expectLater(
        dio.post<dynamic>('/v1/auth/login'),
        throwsA(isA<DioException>()),
      );
      expect(network.hosts, <String>['direct.test']);
    },
  );

  test('a POST marked repeatable moves when it stalls', () async {
    final (Dio dio, _Network network, _) = await _client(<String>{
      'backup.test',
    }, failure: DioExceptionType.receiveTimeout);

    final Response<dynamic> response = await dio.post<dynamic>(
      '/v1/devices/d/xray-client',
      options: Options(extra: <String, dynamic>{kRepeatable: true}),
    );

    expect((response.data as Map<String, dynamic>)['via'], 'backup.test');
    expect(network.hosts, <String>['direct.test', 'backup.test']);
  });

  test('a GET that stalls moves to the next address', () async {
    // A throttled address carries a few requests and then stalls; it never
    // refuses. A GET changes nothing, so sending it elsewhere is safe.
    final (
      Dio dio,
      _Network network,
      SharedPreferences preferences,
    ) = await _client(<String>{
      'backup.test',
    }, failure: DioExceptionType.receiveTimeout);

    final Response<dynamic> response = await dio.get<dynamic>('/v1/me');

    expect((response.data as Map<String, dynamic>)['via'], 'backup.test');
    expect(network.hosts, <String>['direct.test', 'backup.test']);
    expect(preferences.getString(kRememberedRouteKey), _backup);
  });

  test(
    'when neither route answers, the error surfaces after one retry',
    () async {
      final (Dio dio, _Network network, _) = await _client(<String>{});

      await expectLater(
        dio.get<dynamic>('/v1/me'),
        throwsA(isA<DioException>()),
      );
      expect(network.hosts, <String>['direct.test', 'backup.test']);
    },
  );

  test('a GET the address in use holds is raced down the next one', () async {
    // Measured on mobile data: the CDN route answers once, then holds the
    // next request until the receive timeout. The page should not wait.
    final (
      Dio dio,
      _Network network,
      SharedPreferences preferences,
    ) = await _client(
      <String>{'backup.test'},
      stalled: <String>{'direct.test'},
    );

    final Response<dynamic> response = await dio.get<dynamic>('/v1/devices');

    expect((response.data as Map<String, dynamic>)['via'], 'backup.test');
    expect(network.hosts, <String>['direct.test', 'backup.test']);
    expect(preferences.getString(kRememberedRouteKey), _backup);
  });

  test('a POST is never raced', () async {
    // Sent twice, a POST may act twice.
    final (Dio dio, _Network network, _) = await _client(
      <String>{'backup.test'},
      stalled: <String>{'direct.test'},
    );
    final CancelToken cancel = CancelToken();

    final Future<Object?> request = dio
        .post<dynamic>('/v1/auth/login', cancelToken: cancel)
        .then<Object?>((_) => null, onError: (Object error) => error);
    await Future<void>.delayed(const Duration(milliseconds: 200));

    expect(network.hosts, <String>['direct.test']);
    cancel.cancel();
    expect(await request, isA<DioException>());
  });

  test('a fast answer starts no second request', () async {
    final (Dio dio, _Network network, _) = await _client(<String>{
      'direct.test',
      'backup.test',
    });

    await dio.get<dynamic>('/v1/me');
    await Future<void>.delayed(const Duration(milliseconds: 200));

    expect(network.hosts, <String>['direct.test']);
  });

  test('moveOn goes to the next address and stops at the last', () async {
    SharedPreferences.setMockInitialValues(<String, Object>{});
    final SharedPreferences preferences = await SharedPreferences.getInstance();
    final Dio dio = Dio(BaseOptions(baseUrl: _direct));
    final RouteFallbackInterceptor routes = RouteFallbackInterceptor(
      dio: dio,
      routes: <String>[_direct, _backup],
      preferences: () => preferences,
    );

    expect(routes.moveOn(), isTrue);
    expect(routes.current, _backup);
    expect(preferences.getString(kRememberedRouteKey), _backup);
    expect(routes.moveOn(), isFalse);
    expect(routes.current, _backup);
  });
}
