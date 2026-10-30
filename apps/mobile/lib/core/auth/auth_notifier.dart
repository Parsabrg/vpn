import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../hardware_id.dart';
import '../network/api_exception.dart';
import '../network/network_guard.dart';
import '../storage/device_id_store.dart';
import '../storage/secure_token_store.dart';
import '../storage/storage_providers.dart';
import 'auth_repository.dart';
import 'auth_state.dart';
import 'token_pair.dart';
import 'user_principal.dart';

/// Owns every authentication state transition. The single source of truth
/// the router redirect and the Dio auth interceptor both read.
class AuthNotifier extends Notifier<AuthState> {
  late AuthRepository _repository;
  late SecureTokenStore _tokenStore;
  late DeviceIdStore _deviceIdStore;

  /// How often an unreachable server is tried again, on its own.
  static const Duration retryUnreachableAfter = Duration(seconds: 15);

  Timer? _retryTimer;

  @override
  AuthState build() {
    _repository = ref.watch(authRepositoryProvider);
    _tokenStore = ref.watch(secureTokenStoreProvider);
    _deviceIdStore = ref.watch(deviceIdStoreProvider);
    ref.onDispose(() => _retryTimer?.cancel());
    return const AuthAuthenticating();
  }

  /// Runs once at app start (see `main.dart`). Reads any stored refresh
  /// token and attempts to mint a fresh session from it.
  ///
  /// Signed out only when the server rejects the token. When it cannot be
  /// reached, the token is kept and the state is [AuthUnreachable]: the app
  /// opens on its saved settings and keeps trying in the background, rather
  /// than holding the person on a screen that can only wait.
  Future<void> bootstrap() async {
    state = const AuthAuthenticating();
    await _restore();
  }

  /// Tries again to resume the stored session after [AuthUnreachable].
  ///
  /// Stays [AuthUnreachable] while it tries, instead of passing through
  /// [AuthAuthenticating], so a retry does not flash the screen back to
  /// loading every time.
  Future<void> retryRestore() async {
    if (state is! AuthUnreachable) {
      return;
    }
    await _restore();
  }

  Future<void> _restore() async {
    _retryTimer?.cancel();
    final String? storedRefreshToken = await _tokenStore.readRefreshToken();
    if (storedRefreshToken == null) {
      state = const AuthUnauthenticated();
      return;
    }
    try {
      final TokenPair tokens = await runGuarded(
        ref,
        () => _repository.refresh(storedRefreshToken),
      );
      await _tokenStore.writeRefreshToken(tokens.refreshToken);
      state = AuthAuthenticated(tokens: tokens);
      unawaited(_loadMe(tokens.accessToken));
    } catch (error) {
      if (_sessionRejected(error)) {
        await _forgetSession();
        state = const AuthUnauthenticated();
      } else {
        state = const AuthUnreachable();
        // Retried here rather than by whichever screen happens to be
        // showing: recovering a session is this notifier's job, and the
        // screen that used to own the timer is no longer in the way.
        _retryTimer?.cancel();
        _retryTimer = Timer(retryUnreachableAfter, retryRestore);
      }
    }
  }

  /// Whether a failed refresh means the session is really over.
  ///
  /// Only when the server says so: 401 for a token it does not accept,
  /// which includes one revoked for reuse, and 400/403/422 for a request
  /// it will never accept however often it is sent. Not reaching the
  /// server, a timeout, a 503 while its auth store is down, a 429 -- none
  /// of those say anything about the session, and deleting it for them is
  /// what signed people out for being offline.
  static bool _sessionRejected(Object error) {
    return error is NebulaApiException &&
        const <int>{400, 401, 403, 422}.contains(error.statusCode);
  }

  /// Deliberately does *not* pass through [AuthAuthenticating] -- that state
  /// is reserved for app bootstrap, and the router redirects it straight to
  /// `/splash`. Reusing it here would yank the sign-in screen away from
  /// itself mid-submission. The sign-in screen tracks its own in-flight
  /// flag locally instead; this method only ever leaves [state] as whatever
  /// it already was (unauthenticated/session-expired) on failure, or flips
  /// straight to [AuthAuthenticated] on success.
  Future<void> login({
    required String identifier,
    required String password,
    required String deviceName,
    required DevicePlatform platform,
    required String clientVersion,
  }) async {
    final String? rememberedDeviceId = _deviceIdStore.read();
    final String? hardwareId = await ref.read(hardwareIdProvider)();
    late final TokenPair tokens;
    try {
      tokens = await _loginRequest(
        identifier: identifier,
        password: password,
        deviceId: rememberedDeviceId,
        deviceName: deviceName,
        platform: platform,
        clientVersion: clientVersion,
        hardwareId: hardwareId,
      );
    } catch (error) {
      // A portable Windows copy can retain a device id after the server-side
      // device was removed or its database was restored. The API deliberately
      // uses a neutral 401 for that case, so retry once without the stale id;
      // a successful login then writes the current id from /me below. Do not
      // retry network errors or a login that never had a remembered device.
      if (rememberedDeviceId == null || !_loginRejected(error)) {
        rethrow;
      }
      await _deviceIdStore.clear();
      tokens = await _loginRequest(
        identifier: identifier,
        password: password,
        deviceId: null,
        deviceName: deviceName,
        platform: platform,
        clientVersion: clientVersion,
        hardwareId: hardwareId,
      );
    }
    await _tokenStore.writeRefreshToken(tokens.refreshToken);
    state = AuthAuthenticated(tokens: tokens);
    await _loadMe(tokens.accessToken);
  }

  Future<TokenPair> _loginRequest({
    required String identifier,
    required String password,
    required String? deviceId,
    required String deviceName,
    required DevicePlatform platform,
    required String clientVersion,
    required String? hardwareId,
  }) {
    return runGuarded(
      ref,
      () => _repository.login(
        identifier: identifier,
        password: password,
        deviceId: deviceId,
        deviceName: deviceName,
        platform: platform,
        clientVersion: clientVersion,
        hardwareId: hardwareId,
      ),
    );
  }

  static bool _loginRejected(Object error) {
    return error is NebulaApiException &&
        const <int>{400, 401, 403, 422}.contains(error.statusCode);
  }

  Future<void> _loadMe(String accessToken) async {
    try {
      final UserPrincipal me = await runGuarded(
        ref,
        () => _repository.me(accessToken),
      );
      await _deviceIdStore.write(me.deviceId);
      final AuthState current = state;
      if (current is AuthAuthenticated) {
        state = current.copyWith(me: me);
      }
    } catch (_) {
      // Non-fatal: the account screen shows its own loading/error affordance
      // for `me` without invalidating an otherwise-valid session.
    }
  }

  /// Called by [AuthInterceptor] (via [tokenRefresherProvider]) when an
  /// authenticated request's access token has expired mid-session.
  Future<TokenPair> refreshSession() async {
    final AuthState current = state;
    if (current is! AuthAuthenticated) {
      throw StateError('Cannot refresh a session that is not authenticated.');
    }
    try {
      final TokenPair tokens = await runGuarded(
        ref,
        () => _repository.refresh(current.tokens.refreshToken),
      );
      await _tokenStore.writeRefreshToken(tokens.refreshToken);
      state = current.copyWith(tokens: tokens);
      return tokens;
    } catch (error) {
      // Expired only when the server rejected the token -- reuse of an
      // already-rotated one revokes the whole family. Unreachable is not
      // expired: the request fails as offline, the stored session stays,
      // and the next request tries again. No retry loop either way; the
      // caller sees this error once.
      if (_sessionRejected(error)) {
        await expireSession();
      }
      rethrow;
    }
  }

  /// Marks the session revoked (e.g. refresh-token reuse detected) and
  /// clears local credential storage.
  Future<void> expireSession() async {
    await _forgetSession();
    state = const AuthSessionExpired();
  }

  Future<void> logout() async {
    final AuthState current = state;
    // Local state is cleared unconditionally below -- a failed logout call
    // must never strand the user in a signed-in-looking-but-broken state.
    if (current is AuthAuthenticated) {
      unawaited(
        _repository
            .logout(current.tokens.refreshToken)
            .catchError((Object _) {}),
      );
    }
    await _forgetSession();
    state = const AuthUnauthenticated();
  }

  /// Clears what this device held for the session: its tokens and the
  /// tunnel credentials saved for offline connects. The server revokes
  /// those credentials when the session ends, so a copy kept past it only
  /// raises a tunnel that carries nothing -- or one for the wrong account.
  Future<void> _forgetSession() async {
    await _tokenStore.clear();
    try {
      await ref.read(xrayCredentialStoreProvider).clear();
    } catch (_) {
      // An unreadable keystore holds nothing usable either; never a reason
      // to leave someone signed in.
    }
  }

  String? get currentAccessToken {
    final AuthState current = state;
    return current is AuthAuthenticated ? current.tokens.accessToken : null;
  }
}

final authNotifierProvider = NotifierProvider<AuthNotifier, AuthState>(
  AuthNotifier.new,
);
