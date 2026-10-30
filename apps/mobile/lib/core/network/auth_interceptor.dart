import 'dart:async';

import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../auth/auth_notifier.dart';
import '../auth/token_pair.dart';
import 'api_client.dart';
import 'api_exception.dart';
import 'token_refresher.dart';

/// Paths that never carry a bearer token, per the API contract: they either
/// authenticate the caller a different way (refresh/login take a
/// credential in the body) or require no identity at all (account
/// requests, password reset). A 401 from one of these is a genuine
/// authentication failure, not an expired-access-token situation, so it
/// must never trigger the refresh-and-retry flow below.
bool isUnauthenticatedPath(String path) {
  const List<String> exactPaths = <String>[
    '/v1/auth/login',
    '/v1/auth/refresh',
    '/v1/auth/password-reset/request',
    '/v1/auth/password-reset/confirm',
  ];
  if (exactPaths.contains(path)) {
    return true;
  }
  return path.startsWith('/v1/account-requests');
}

/// Attaches the current access token to every authenticated request, and on
/// a 401 from one of them, serializes a token refresh (via [TokenRefresher])
/// and retries the request exactly once with the new token.
///
/// Holds a [Ref] rather than pre-resolved dependencies so this interceptor
/// can be constructed without eagerly building [tokenRefresherProvider] or
/// [authNotifierProvider] -- both are only read lazily, inside request-time
/// callbacks, long after every provider in the graph already exists. That is
/// what keeps `dioProvider -> authRepositoryProvider -> dioProvider` from
/// being a build-time circular dependency: nothing here is resolved during
/// any provider's own `build()`, only inside `onRequest`/`onError`, which
/// run after the whole provider graph is already constructed.
class AuthInterceptor extends Interceptor {
  AuthInterceptor(Ref ref)
    : this.withDependencies(
        accessToken: () =>
            ref.read(authNotifierProvider.notifier).currentAccessToken,
        refresh: () => ref.read(tokenRefresherProvider).refresh(),
        fetch: (RequestOptions options) =>
            ref.read(dioProvider).fetch<dynamic>(options),
      );

  /// For tests: the same behaviour over plain functions, so it can be driven
  /// with a fake transport and no provider graph.
  AuthInterceptor.withDependencies({
    required this._accessToken,
    required this._refresh,
    required this._fetch,
  });

  /// Set on the one retry a 401 earns. A request carrying it is never
  /// refreshed again: before this, the retry went back through this same
  /// interceptor, and a second 401 -- a session revoked between refresh and
  /// retry, a clock the server disagrees with -- started another refresh,
  /// then another retry, without end.
  static const String retriedKey = 'nebula.auth.retried';

  final String? Function() _accessToken;
  final Future<TokenPair> Function() _refresh;
  final Future<Response<dynamic>> Function(RequestOptions) _fetch;

  @override
  void onRequest(RequestOptions options, RequestInterceptorHandler handler) {
    // A retry already carries the token its refresh produced.
    if (!isUnauthenticatedPath(options.path) &&
        options.extra[retriedKey] != true) {
      final String? accessToken = _accessToken();
      if (accessToken != null) {
        options.headers['Authorization'] = 'Bearer $accessToken';
      }
    }
    handler.next(options);
  }

  @override
  void onError(DioException err, ErrorInterceptorHandler handler) {
    final RequestOptions request = err.requestOptions;
    final bool eligibleForRefresh =
        err.response?.statusCode == 401 &&
        !isUnauthenticatedPath(request.path) &&
        request.headers.containsKey('Authorization') &&
        request.extra[retriedKey] != true;

    if (!eligibleForRefresh) {
      handler.next(err);
      return;
    }

    unawaited(_retryAfterRefresh(err, handler));
  }

  Future<void> _retryAfterRefresh(
    DioException err,
    ErrorInterceptorHandler handler,
  ) async {
    final RequestOptions request = err.requestOptions;
    try {
      final TokenPair tokens = await _refresh();
      final RequestOptions retryOptions = request.copyWith(
        headers: <String, dynamic>{
          ...request.headers,
          'Authorization': 'Bearer ${tokens.accessToken}',
        },
        extra: <String, dynamic>{...request.extra, retriedKey: true},
      );
      final Response<dynamic> response = await _fetch(retryOptions);
      handler.resolve(response);
    } on DioException catch (retryError) {
      // Refresh succeeded but the retried request itself failed again --
      // surface that failure as-is, no further retry.
      handler.next(retryError);
    } on NebulaConnectivityException catch (refreshError) {
      // The refresh never reached the server. That is not the server
      // refusing anyone: surfaced as the 401 it followed, a network hiccup
      // read "Authentication was not accepted" (Windows, 2026-10-18), while
      // the session itself was fine. Reported as what it was.
      handler.next(
        DioException(
          requestOptions: request,
          type: DioExceptionType.connectionError,
          error: refreshError,
        ),
      );
    } on NebulaApiException catch (refreshError) {
      if (AuthNotifier.sessionRejected(refreshError)) {
        // Refused for real: AuthNotifier has expired the session; the
        // original 401 is what the caller sees, never a retry loop.
        handler.next(err);
        return;
      }
      // The server answered the refresh but did not judge the session: a
      // 429 (rate limited) or a 503 (its auth store down). The session is
      // fine; the caller sees that answer, not the 401 it followed, which
      // read as signed out and took a connected tunnel down (2026-10-30).
      handler.next(
        DioException(
          requestOptions: request,
          type: DioExceptionType.badResponse,
          error: refreshError,
          response: Response<dynamic>(
            requestOptions: request,
            statusCode: refreshError.statusCode,
            data: <String, dynamic>{'detail': refreshError.detail},
            headers: Headers.fromMap(<String, List<String>>{
              if (refreshError.retryAfter != null)
                'retry-after': <String>[
                  '${refreshError.retryAfter!.inSeconds}',
                ],
            }),
          ),
        ),
      );
    } catch (_) {
      // Refresh itself failed (e.g. session revoked) -- AuthNotifier has
      // already transitioned to AuthSessionExpired and cleared storage via
      // TokenRefresher's underlying call; the original 401 is what the
      // caller sees, never a retry loop.
      handler.next(err);
    }
  }
}

final tokenRefresherProvider = Provider<TokenRefresher>((Ref ref) {
  return TokenRefresher(
    () => ref.read(authNotifierProvider.notifier).refreshSession(),
  );
});
