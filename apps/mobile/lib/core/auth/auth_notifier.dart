import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';

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
  late final AuthRepository _repository;
  late final SecureTokenStore _tokenStore;
  late final DeviceIdStore _deviceIdStore;

  @override
  AuthState build() {
    _repository = ref.watch(authRepositoryProvider);
    _tokenStore = ref.watch(secureTokenStoreProvider);
    _deviceIdStore = ref.watch(deviceIdStoreProvider);
    return const AuthAuthenticating();
  }

  /// Runs once at app start (see `main.dart`). Reads any stored refresh
  /// token and attempts to mint a fresh session from it; falls back to
  /// signed-out on any failure, including offline, so the app never gets
  /// stuck on the splash screen.
  Future<void> bootstrap() async {
    state = const AuthAuthenticating();
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
    } catch (_) {
      await _tokenStore.clear();
      state = const AuthUnauthenticated();
    }
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
    final TokenPair tokens = await runGuarded(
      ref,
      () => _repository.login(
        identifier: identifier,
        password: password,
        deviceId: _deviceIdStore.read(),
        deviceName: deviceName,
        platform: platform,
        clientVersion: clientVersion,
      ),
    );
    await _tokenStore.writeRefreshToken(tokens.refreshToken);
    state = AuthAuthenticated(tokens: tokens);
    await _loadMe(tokens.accessToken);
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
    } catch (_) {
      // A failed refresh here always means the session is gone -- either
      // reuse of an already-rotated refresh token was detected server-side
      // (the whole token family is revoked), or the API is unreachable and
      // there is no safe way to keep serving requests with a token that may
      // already be expired. Either way, no retry loop: the caller sees this
      // error once and the app moves to a definite signed-out state.
      await expireSession();
      rethrow;
    }
  }

  /// Marks the session revoked (e.g. refresh-token reuse detected) and
  /// clears local credential storage.
  Future<void> expireSession() async {
    await _tokenStore.clear();
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
    await _tokenStore.clear();
    state = const AuthUnauthenticated();
  }

  String? get currentAccessToken {
    final AuthState current = state;
    return current is AuthAuthenticated ? current.tokens.accessToken : null;
  }
}

final authNotifierProvider = NotifierProvider<AuthNotifier, AuthState>(
  AuthNotifier.new,
);
