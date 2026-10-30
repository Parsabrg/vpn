import 'dart:async';

import '../auth/token_pair.dart';

/// Performs the actual refresh (network call plus persisting the result).
/// Kept as a zero-argument function type -- not a full repository interface,
/// and deliberately not parameterized by a refresh-token value -- so
/// [TokenRefresher] has the smallest possible dependency surface and is
/// trivially testable in isolation from Dio/Riverpod. The current refresh
/// token always comes from whatever the caller's own source of truth holds
/// at call time (see `AuthNotifier.refreshSession`), never from a value
/// threaded through by an individual request -- that avoids concurrent
/// callers ever racing on which refresh token is "current."
typedef RefreshCall = Future<TokenPair> Function();

/// Serializes concurrent token-refresh attempts behind a single in-flight
/// [Future].
///
/// The access token is short-lived (15 minutes by default); several
/// requests can independently notice it has expired and call [refresh] at
/// nearly the same moment. Without deduplication, each would fire its own
/// `/v1/auth/refresh` call -- and because refresh tokens rotate on use, all
/// but the first would be racing against an already-consumed token and
/// fail. This class guarantees exactly one network call services every
/// concurrent caller in a given refresh window: the first caller starts the
/// call and creates a [Completer]; every other caller that arrives before
/// it finishes awaits the *same* [Completer]'s future and receives the same
/// result (or the same error).
class TokenRefresher {
  TokenRefresher(this._refreshCall);

  final RefreshCall _refreshCall;
  Completer<TokenPair>? _inFlight;

  Future<TokenPair> refresh() {
    final Completer<TokenPair>? existing = _inFlight;
    if (existing != null) {
      return existing.future;
    }

    final Completer<TokenPair> completer = Completer<TokenPair>();
    _inFlight = completer;

    _refreshCall()
        .then((TokenPair pair) => completer.complete(pair))
        .catchError((Object error, StackTrace stackTrace) {
          completer.completeError(error, stackTrace);
        })
        .whenComplete(() {
          // Only the refresh that owns the current window clears it -- a
          // stale `whenComplete` from an already-superseded attempt must not
          // clobber a newer in-flight refresh.
          if (identical(_inFlight, completer)) {
            _inFlight = null;
          }
        });

    return completer.future;
  }
}
