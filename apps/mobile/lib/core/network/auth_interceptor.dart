import 'dart:async';

import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../auth/auth_notifier.dart';
import '../auth/token_pair.dart';
import 'api_client.dart';
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
  AuthInterceptor(this._ref);

  final Ref _ref;

  @override
  void onRequest(RequestOptions options, RequestInterceptorHandler handler) {
    if (!isUnauthenticatedPath(options.path)) {
      final String? accessToken = _ref
          .read(authNotifierProvider.notifier)
          .currentAccessToken;
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
        request.headers.containsKey('Authorization');

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
    final TokenRefresher refresher = _ref.read(tokenRefresherProvider);
    try {
      final TokenPair tokens = await refresher.refresh();
      final RequestOptions retryOptions = request.copyWith(
        headers: <String, dynamic>{
          ...request.headers,
          'Authorization': 'Bearer ${tokens.accessToken}',
        },
      );
      final Dio dio = _ref.read(dioProvider);
      final Response<dynamic> response = await dio.fetch<dynamic>(retryOptions);
      handler.resolve(response);
    } on DioException catch (retryError) {
      // Refresh succeeded but the retried request itself failed again --
      // surface that failure as-is, no further retry.
      handler.next(retryError);
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
