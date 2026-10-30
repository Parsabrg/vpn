import 'dart:ui';

import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/network/api_exception.dart';
import 'package:nebula_mobile/core/network/error_copy.dart';
import 'package:nebula_mobile/core/wireguard/windows_wireguard_tunnel.dart';
import 'package:nebula_mobile/core/xray/xray_tunnel_controller.dart';
import 'package:nebula_mobile/l10n/app_localizations.dart';

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

  group('a spent traffic allowance', () {
    test('is told apart by status, not by wording', () {
      // The server owns the wording; matching on it would break the first
      // time somebody rephrased it. Nothing else in this API answers 402.
      const NebulaApiException quota = NebulaApiException(
        statusCode: 402,
        detail: 'anything at all',
      );
      const NebulaApiException other = NebulaApiException(
        statusCode: 400,
        detail: 'Data limit reached',
      );

      expect(quota.isQuotaExhausted, isTrue);
      expect(other.isQuotaExhausted, isFalse);
    });

    test('says so, and says what would actually fix it', () {
      // Retrying cannot help, and there is exactly one thing that can.
      const NebulaApiException error = NebulaApiException(
        statusCode: 402,
        detail: 'Data limit reached',
      );

      final String message = userFacingErrorMessage(
        error,
        lookupAppText(const Locale('en')),
      );

      expect(message, contains('Data limit reached'));
      expect(message, contains('administrator'));
    });
  });

  group('in a language other than English', () {
    final AppText persian = lookupAppText(const Locale('fa'));
    final AppText english = lookupAppText(const Locale('en'));

    test('English shows the server detail exactly as written', () {
      const NebulaApiException error = NebulaApiException(
        statusCode: 401,
        detail: 'Authentication was not accepted',
      );

      expect(
        userFacingErrorMessage(error, english),
        'Authentication was not accepted',
      );
    });

    test('Persian never shows the English detail from the server', () {
      // The server writes its details in English. Showing one mid-sentence in
      // a right-to-left screen is exactly the half-translated app this exists
      // to avoid, and the details are generic enough that their kind is all
      // they carry.
      for (final int status in <int>[400, 401, 403, 404, 409, 422, 503]) {
        final String message = userFacingErrorMessage(
          NebulaApiException(
            statusCode: status,
            detail: 'Authentication was not accepted',
          ),
          persian,
        );
        expect(message, isNot(contains('Authentication')), reason: '$status');
        expect(message, isNotEmpty, reason: '$status');
      }
    });

    test('shows the messages of the desktop tunnel helpers', () {
      // They say which step failed -- the prompt was refused, a tool is
      // missing -- and the generic sentence would hide exactly that.
      for (final String message in <String>[
        'Windows did not finish configuring the VPN routes.',
        'Linux VPN permission was not granted.',
        'Linux needs WireGuard tools for this protocol. Install the '
            'wireguard-tools package.',
      ]) {
        expect(userFacingErrorMessage(StateError(message), english), message);
      }
      expect(
        userFacingErrorMessage(StateError('something else'), english),
        english.errorGeneric,
      );
    });

    test('keeps unavailable and not-found distinct from a refusal', () {
      // "Try again shortly" and "that was refused" send somebody in
      // different directions, so they must not collapse into one sentence.
      String forStatus(int status) => userFacingErrorMessage(
        NebulaApiException(statusCode: status, detail: 'x'),
        persian,
      );

      expect(forStatus(503), persian.errorUnavailable);
      expect(forStatus(404), persian.errorNotFound);
      expect(forStatus(401), persian.errorNotAccepted);
    });

    test('says the server is under maintenance', () {
      const NebulaApiException locked = NebulaApiException(
        statusCode: 423,
        detail: 'This server is under maintenance. Try again later.',
      );

      expect(
        userFacingErrorMessage(locked, persian),
        persian.errorServerMaintenance,
      );
      expect(
        userFacingErrorMessage(locked, english),
        english.errorServerMaintenance,
      );
    });

    test('says the account expired, in English too', () {
      const NebulaApiException expired = NebulaApiException(
        statusCode: 403,
        detail: 'account_expired',
      );

      expect(
        userFacingErrorMessage(expired, persian),
        persian.errorAccountExpired,
      );
      expect(
        userFacingErrorMessage(expired, english),
        english.errorAccountExpired,
      );
    });

    test('says the device limit was reached, in English too', () {
      // The server sends a code, not a sentence; English would otherwise
      // show the raw code.
      const NebulaApiException atLimit = NebulaApiException(
        statusCode: 403,
        detail: 'device_limit_reached',
      );

      expect(
        userFacingErrorMessage(atLimit, persian),
        persian.errorDeviceLimitReached,
      );
      expect(
        userFacingErrorMessage(atLimit, english),
        english.errorDeviceLimitReached,
      );
      expect(
        const NebulaApiException(
          statusCode: 403,
          detail: 'x',
        ).isDeviceLimitReached,
        isFalse,
      );
    });

    test('translates the messages the app writes itself', () {
      expect(
        userFacingErrorMessage(const NebulaConnectivityException('x'), persian),
        persian.errorOffline,
      );
      expect(
        userFacingErrorMessage(const WireGuardNoAnswer(), persian),
        persian.errorWireguardNoHandshake,
      );
      expect(
        userFacingErrorMessage(
          const NebulaApiException(statusCode: 402, detail: 'x'),
          persian,
        ),
        persian.errorQuotaExhausted,
      );
      expect(
        userFacingErrorMessage(StateError('x'), persian),
        persian.errorGeneric,
      );
    });
  });

  test(
    'a tunnel that never came up is a protocol that did not get through',
    () {
      // Hysteria2 on a network that drops UDP: the engine never reports up.
      // "Something went wrong" sent nobody to the protocol list.
      final AppText english = lookupAppText(const Locale('en'));
      expect(
        userFacingErrorMessage(const TunnelStartTimeout(), english),
        english.errorTunnelNoTraffic,
      );
    },
  );
}
