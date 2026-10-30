import 'dart:async';
import 'dart:convert';
import 'dart:io' show HandshakeException;

import 'package:dio/dio.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Where the keys the app remembers about routes live, shared with
/// [ApiRouteSync] which writes the learned list.
const String kRememberedRouteKey = 'nebula.api_route';
const String kRememberedRouteAtKey = 'nebula.api_route_at';
const String kLearnedRoutesKey = 'nebula.api_routes';

/// Set in a request's `extra` when sending it twice does no harm, so a stall
/// may move it to the next address like a GET.
const String kRepeatable = 'nebula.repeatable';

/// Moves the API between the addresses it can be reached at, when the one in
/// use cannot be reached at all.
///
/// The app is built knowing a direct address and a Cloudflare-proxied backup.
/// It also keeps whatever list the server last told it about (`/v1/routes`),
/// so an address added after this build shipped can still be used -- that is
/// the difference between answering a block with a configuration change and
/// answering it with a release, which is what every 0.1.10 install is waiting
/// for.
///
/// Only a request that never arrived is retried: a connection that could not
/// be made, timed out while connecting, or failed its TLS handshake. Those
/// are safe to send again even when they change something, like a sign-in; a
/// timeout waiting for a *response* is not, because the server may have acted
/// on it -- except for a GET, which changes nothing. That exception matters:
/// a throttled address does not refuse, it carries a few requests and then
/// stalls (measured from Iran on 2026-10-06, direct and through Cloudflare),
/// so a stalled GET is how the app learns to move.
///
/// The address that worked is remembered, so a phone on a blocked network
/// does not spend the connect timeout on a dead address at every launch.
class RouteFallbackInterceptor extends Interceptor {
  RouteFallbackInterceptor({
    required this.dio,
    required this.routes,
    this.preferences,
    this.hedgeAfter = const Duration(milliseconds: 2500),
  }) : assert(routes.isNotEmpty, 'at least the build-time address');

  final Dio dio;

  /// The addresses this app was paired with (or built with), in the order to
  /// try them. Replaced by [retarget] when the app is paired again.
  List<String> routes;

  /// Read lazily, and allowed to be absent: where the remembered address and
  /// the learned list are kept. Looking them up at construction would make
  /// building the API client depend on storage being ready.
  final SharedPreferences? Function()? preferences;

  /// How long a GET waits on the address in use before the same request also
  /// goes down the next one. A throttled address does not fail, it stalls,
  /// and a stall only ends at the receive timeout -- measured on mobile data
  /// on 2026-10-17, the CDN route answered one request and held the next for
  /// 40 s, so a page waited 10 s per request. Racing them, the first answer
  /// wins and its address is the one used next.
  final Duration hedgeAfter;

  static const String _retriedKey = 'nebula.route_retried';

  String? _current;

  /// Everything known, built-in first, without duplicates.
  List<String> get known {
    final List<String> all = <String>[...routes];
    final String? stored = preferences?.call()?.getString(kLearnedRoutesKey);
    if (stored != null) {
      try {
        for (final Object? entry in jsonDecode(stored) as List<Object?>) {
          if (entry is String && entry.startsWith('https://')) {
            if (!all.contains(entry)) {
              all.add(entry);
            }
          }
        }
      } on FormatException {
        // Written by a build whose shape has since changed, or truncated.
        // The built-in addresses are enough to carry on with.
      }
    }
    return all;
  }

  /// How long a fallback address is kept in preference to the first one.
  /// Addresses come back: a throttled one is swapped for a new one, a
  /// block is lifted. Without this a phone that once fell back stayed on
  /// the fallback for good -- a web-host front with a monthly allowance, or
  /// a CDN slower than the server itself.
  static const Duration rememberFallbackFor = Duration(hours: 1);

  String get current {
    final SharedPreferences? stored = preferences?.call();
    final String? remembered = stored?.getString(kRememberedRouteKey);
    final int? at = stored?.getInt(kRememberedRouteAtKey);
    final bool fresh =
        at != null &&
        DateTime.now().difference(DateTime.fromMillisecondsSinceEpoch(at)) <
            rememberFallbackFor;
    return _current ??=
        remembered != null && known.contains(remembered) && fresh
        ? remembered
        : routes.first;
  }

  /// Points every later request at [newRoutes], the addresses of a newly
  /// paired deployment. What was learned from the previous one -- its extra
  /// addresses and the one that last worked -- belongs to it and is dropped:
  /// kept, it would send this deployment's credentials to that one.
  void retarget(List<String> newRoutes) {
    assert(newRoutes.isNotEmpty, 'at least the paired address');
    routes = newRoutes;
    _current = null;
    final SharedPreferences? stored = preferences?.call();
    stored?.remove(kRememberedRouteKey);
    stored?.remove(kRememberedRouteAtKey);
    stored?.remove(kLearnedRoutesKey);
    dio.options.baseUrl = newRoutes.first;
  }

  /// Moves every later request to the address after the one in use, and
  /// remembers it. False when there is none left.
  ///
  /// For a tunnel that came up and carried nothing: its address was handed
  /// out by the API on the route in use, so asking again over the next route
  /// is how the tunnel follows it (a CDN, then a web-host front).
  // ponytail: never moves back on its own; a phone that reached the last
  // route stays there until it fails. Add a periodic retry of the first route
  // if the front's quota becomes the limit.
  bool moveOn() {
    final List<String> all = known;
    final int at = all.indexOf(current);
    if (at < 0 || at + 1 >= all.length) {
      return false;
    }
    _use(all[at + 1]);
    return true;
  }

  void _use(String baseUrl) {
    _current = baseUrl;
    dio.options.baseUrl = baseUrl;
    preferences?.call()?.setString(kRememberedRouteKey, baseUrl);
    preferences?.call()?.setInt(
      kRememberedRouteAtKey,
      DateTime.now().millisecondsSinceEpoch,
    );
  }

  @override
  void onRequest(RequestOptions options, RequestInterceptorHandler handler) {
    if (options.extra[_retriedKey] != true && known.contains(options.baseUrl)) {
      options.baseUrl = current;
      if (_repeatable(options) && known.length > 1) {
        unawaited(_race(options, handler));
        return;
      }
    }
    handler.next(options);
  }

  /// Sends [options] down the address in use, and down the next one each
  /// time [hedgeAfter] passes without an answer or an attempt fails before
  /// one arrives. The first answer is the request's; the others are
  /// cancelled.
  Future<void> _race(
    RequestOptions options,
    RequestInterceptorHandler handler,
  ) async {
    final String first = current;
    final List<String> order = <String>[
      first,
      ...known.where((String route) => route != first),
    ];
    final Completer<Response<dynamic>> answer = Completer<Response<dynamic>>();
    final List<CancelToken> attempts = <CancelToken>[];
    unawaited(
      options.cancelToken?.whenCancel.then((DioException reason) {
        if (!answer.isCompleted) {
          answer.completeError(reason);
        }
      }),
    );
    int failed = 0;
    DioException? lastError;
    Timer? next;

    void start() {
      if (answer.isCompleted || attempts.length >= order.length) {
        return;
      }
      final String route = order[attempts.length];
      final CancelToken attempt = CancelToken();
      attempts.add(attempt);
      next?.cancel();
      next = Timer(hedgeAfter, start);
      dio
          .fetch<dynamic>(
            options.copyWith(
              baseUrl: route,
              cancelToken: attempt,
              extra: <String, dynamic>{...options.extra, _retriedKey: true},
            ),
          )
          .then(
            (Response<dynamic> response) {
              if (!answer.isCompleted) {
                if (route != first) {
                  _use(route);
                }
                answer.complete(response);
              }
            },
            onError: (Object error) {
              if (answer.isCompleted) {
                return;
              }
              final DioException failure = error is DioException
                  ? error
                  : DioException(requestOptions: options, error: error);
              if (!_retryable(failure)) {
                // This address answered; it just did not like the request.
                answer.completeError(failure);
                return;
              }
              lastError = failure;
              failed++;
              if (attempts.length < order.length) {
                start();
              } else if (failed == attempts.length) {
                answer.completeError(lastError!);
              }
            },
          );
    }

    start();
    try {
      handler.resolve(await answer.future);
    } on DioException catch (error) {
      handler.reject(error);
    } finally {
      next?.cancel();
      for (final CancelToken attempt in attempts) {
        attempt.cancel();
      }
    }
  }

  @override
  Future<void> onError(
    DioException err,
    ErrorInterceptorHandler handler,
  ) async {
    final RequestOptions request = err.requestOptions;
    if (!_retryable(err) ||
        request.extra[_retriedKey] == true ||
        !known.contains(request.baseUrl)) {
      handler.next(err);
      return;
    }
    DioException lastError = err;
    for (final String candidate in known) {
      if (candidate == request.baseUrl) {
        continue;
      }
      try {
        final Response<dynamic> response = await dio.fetch<dynamic>(
          request.copyWith(
            baseUrl: candidate,
            extra: <String, dynamic>{...request.extra, _retriedKey: true},
          ),
        );
        _use(candidate);
        handler.resolve(response);
        return;
      } on DioException catch (retryError) {
        lastError = retryError;
        if (!_retryable(retryError)) {
          // This address answered; it just did not like the request. Trying
          // the next one would turn a refusal into a different refusal.
          break;
        }
      }
    }
    handler.next(lastError);
  }

  static bool _retryable(DioException err) =>
      _neverArrived(err) ||
      (err.type == DioExceptionType.receiveTimeout &&
          _repeatable(err.requestOptions)) ||
      (_notFromNebula(err) &&
          (_repeatable(err.requestOptions) ||
              (err.response?.statusCode ?? 500) < 500));

  /// A refusal written by something in front of the API rather than by it:
  /// the API answers every error as JSON with a `detail`. A disabled Vercel
  /// front answered "402 Payment required" in plain text, which the app read
  /// as the account's data limit and stopped there (2026-10-29), while the
  /// API itself answered on every other route. A 4xx from a front never
  /// reached the API, so even a POST may move; a 5xx (a CDN's origin
  /// timeout) may have, so only a repeatable request does.
  static bool _notFromNebula(DioException err) {
    if (err.type != DioExceptionType.badResponse) {
      return false;
    }
    final Object? body = err.response?.data;
    return !(body is Map && body.containsKey('detail'));
  }

  static bool _repeatable(RequestOptions options) =>
      options.method.toUpperCase() == 'GET' ||
      options.extra[kRepeatable] == true;

  static bool _neverArrived(DioException err) =>
      err.type == DioExceptionType.connectionTimeout ||
      err.type == DioExceptionType.connectionError ||
      err.error is HandshakeException;
}
