import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/network/api_exception.dart';

RequestOptions _options() => RequestOptions(path: '/v1/auth/login');

void main() {
  test('a connection error becomes a connectivity exception', () {
    final DioException error = DioException(
      requestOptions: _options(),
      type: DioExceptionType.connectionError,
      message: 'Failed host lookup',
    );

    expect(translateDioException(error), isA<NebulaConnectivityException>());
  });

  test('a plain string detail is used as-is', () {
    final RequestOptions options = _options();
    final Response<dynamic> response = Response<dynamic>(
      requestOptions: options,
      statusCode: 401,
      data: <String, dynamic>{'detail': 'Authentication was not accepted'},
    );
    final DioException error = DioException(
      requestOptions: options,
      response: response,
      type: DioExceptionType.badResponse,
    );

    final NebulaApiException translated =
        translateDioException(error) as NebulaApiException;

    expect(translated.statusCode, 401);
    expect(translated.detail, 'Authentication was not accepted');
    expect(translated.isUnauthorized, isTrue);
  });

  test('a list of validation errors is joined into one message', () {
    final RequestOptions options = _options();
    final Response<dynamic> response = Response<dynamic>(
      requestOptions: options,
      statusCode: 422,
      data: <String, dynamic>{
        'detail': <Map<String, dynamic>>[
          <String, dynamic>{
            'type': 'string_too_short',
            'loc': <String>['body', 'password'],
            'msg': 'String should have at least 12 characters',
          },
        ],
      },
    );
    final DioException error = DioException(
      requestOptions: options,
      response: response,
      type: DioExceptionType.badResponse,
    );

    final NebulaApiException translated =
        translateDioException(error) as NebulaApiException;

    expect(translated.detail, 'String should have at least 12 characters');
  });

  test('a Retry-After header becomes a Duration and marks rate limiting', () {
    final RequestOptions options = _options();
    final Response<dynamic> response = Response<dynamic>(
      requestOptions: options,
      statusCode: 429,
      data: <String, dynamic>{'detail': 'Request was not accepted'},
      headers: Headers.fromMap(<String, List<String>>{
        'retry-after': <String>['5'],
      }),
    );
    final DioException error = DioException(
      requestOptions: options,
      response: response,
      type: DioExceptionType.badResponse,
    );

    final NebulaApiException translated =
        translateDioException(error) as NebulaApiException;

    expect(translated.isRateLimited, isTrue);
    expect(translated.retryAfter, const Duration(seconds: 5));
  });
}
