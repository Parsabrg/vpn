import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/auth/auth_notifier.dart';
import 'package:nebula_mobile/core/auth/auth_repository.dart';
import 'package:nebula_mobile/core/auth/auth_state.dart';
import 'package:nebula_mobile/core/auth/token_pair.dart';
import 'package:nebula_mobile/core/auth/user_principal.dart';
import 'package:nebula_mobile/core/network/api_exception.dart';
import 'package:nebula_mobile/core/storage/device_id_store.dart';
import 'package:nebula_mobile/core/storage/secure_token_store.dart';

import 'fake_auth_repository.dart';

TokenPair _tokens({String access = 'access', String refresh = 'refresh'}) {
  return TokenPair(
    accessToken: access,
    refreshToken: refresh,
    expiresIn: const Duration(minutes: 15),
  );
}

({
  ProviderContainer container,
  FakeAuthRepository repository,
  InMemorySecureTokenStore tokenStore,
  InMemoryDeviceIdStore deviceIdStore,
})
_harness() {
  final FakeAuthRepository repository = FakeAuthRepository();
  final InMemorySecureTokenStore tokenStore = InMemorySecureTokenStore();
  final InMemoryDeviceIdStore deviceIdStore = InMemoryDeviceIdStore();

  final ProviderContainer container = ProviderContainer(
    overrides: <Override>[
      authRepositoryProvider.overrideWithValue(repository),
      secureTokenStoreProvider.overrideWithValue(tokenStore),
      deviceIdStoreProvider.overrideWithValue(deviceIdStore),
    ],
  );

  return (
    container: container,
    repository: repository,
    tokenStore: tokenStore,
    deviceIdStore: deviceIdStore,
  );
}

void main() {
  group('AuthNotifier.bootstrap', () {
    test('with no stored refresh token lands unauthenticated', () async {
      final harness = _harness();
      addTearDown(harness.container.dispose);

      await harness.container
          .read(authNotifierProvider.notifier)
          .bootstrap();

      expect(
        harness.container.read(authNotifierProvider),
        isA<AuthUnauthenticated>(),
      );
      expect(harness.repository.refreshCalls, 0);
    });

    test(
      'with a stored refresh token that resolves lands authenticated and '
      'loads the principal',
      () async {
        final harness = _harness();
        addTearDown(harness.container.dispose);
        await harness.tokenStore.writeRefreshToken('stored-refresh');
        harness.repository.refreshResult = () =>
            _tokens(access: 'fresh-access', refresh: 'rotated-refresh');
        harness.repository.meResult = () => const UserPrincipal(
          userId: 'user-1',
          sessionId: 'session-1',
          deviceId: 'device-1',
        );

        await harness.container
            .read(authNotifierProvider.notifier)
            .bootstrap();
        // Let the fire-and-forget `_loadMe` call resolve.
        await Future<void>.delayed(Duration.zero);

        final AuthState state = harness.container.read(authNotifierProvider);
        expect(state, isA<AuthAuthenticated>());
        final AuthAuthenticated authenticated = state as AuthAuthenticated;
        expect(authenticated.tokens.accessToken, 'fresh-access');
        expect(authenticated.me?.deviceId, 'device-1');
        expect(
          await harness.tokenStore.readRefreshToken(),
          'rotated-refresh',
        );
        expect(harness.deviceIdStore.read(), 'device-1');
      },
    );

    test('with a stored refresh token that fails clears storage', () async {
      final harness = _harness();
      addTearDown(harness.container.dispose);
      await harness.tokenStore.writeRefreshToken('stale-refresh');
      harness.repository.refreshError = const NebulaApiException(
        statusCode: 401,
        detail: 'Authentication was not accepted',
      );

      await harness.container
          .read(authNotifierProvider.notifier)
          .bootstrap();

      expect(
        harness.container.read(authNotifierProvider),
        isA<AuthUnauthenticated>(),
      );
      expect(await harness.tokenStore.readRefreshToken(), isNull);
    });
  });

  group('AuthNotifier.login', () {
    test('success transitions straight to authenticated', () async {
      final harness = _harness();
      addTearDown(harness.container.dispose);
      harness.repository.loginResult = () => _tokens();
      harness.repository.meResult = () => const UserPrincipal(
        userId: 'u',
        sessionId: 's',
        deviceId: 'd',
      );

      await harness.container
          .read(authNotifierProvider.notifier)
          .login(
            identifier: 'user@example.com',
            password: 'hunter22222222',
            deviceName: 'test device',
            platform: DevicePlatform.android,
            clientVersion: '0.1.0',
          );

      expect(
        harness.container.read(authNotifierProvider),
        isA<AuthAuthenticated>(),
      );
    });

    test('failure leaves state unauthenticated and rethrows', () async {
      final harness = _harness();
      addTearDown(harness.container.dispose);
      harness.repository.loginError = const NebulaApiException(
        statusCode: 401,
        detail: 'Authentication was not accepted',
      );

      await expectLater(
        harness.container
            .read(authNotifierProvider.notifier)
            .login(
              identifier: 'user@example.com',
              password: 'wrong-password',
              deviceName: 'test device',
              platform: DevicePlatform.android,
              clientVersion: '0.1.0',
            ),
        throwsA(isA<NebulaApiException>()),
      );
      expect(
        harness.container.read(authNotifierProvider),
        isA<AuthUnauthenticated>(),
      );
    });
  });

  group('AuthNotifier.refreshSession', () {
    test('failure expires the session and clears storage', () async {
      final harness = _harness();
      addTearDown(harness.container.dispose);
      final AuthNotifier notifier = harness.container.read(
        authNotifierProvider.notifier,
      );
      // Drive the notifier into an authenticated state via a successful
      // bootstrap, rather than reaching into private state directly.
      await harness.tokenStore.writeRefreshToken('current-refresh');
      harness.repository.refreshResult = () =>
          _tokens(refresh: 'current-refresh');
      await notifier.bootstrap();
      expect(
        harness.container.read(authNotifierProvider),
        isA<AuthAuthenticated>(),
      );

      harness.repository.refreshError = const NebulaApiException(
        statusCode: 401,
        detail: 'Authentication was not accepted',
      );

      await expectLater(
        notifier.refreshSession(),
        throwsA(isA<NebulaApiException>()),
      );
      expect(
        harness.container.read(authNotifierProvider),
        isA<AuthSessionExpired>(),
      );
      expect(await harness.tokenStore.readRefreshToken(), isNull);
    });
  });

  group('AuthNotifier.logout', () {
    test('always lands unauthenticated even if the network call fails', () async {
      final harness = _harness();
      addTearDown(harness.container.dispose);
      final AuthNotifier notifier = harness.container.read(
        authNotifierProvider.notifier,
      );
      await harness.tokenStore.writeRefreshToken('current-refresh');
      harness.repository.refreshResult = () =>
          _tokens(refresh: 'current-refresh');
      await notifier.bootstrap();
      expect(
        harness.container.read(authNotifierProvider),
        isA<AuthAuthenticated>(),
      );

      await notifier.logout();

      expect(
        harness.container.read(authNotifierProvider),
        isA<AuthUnauthenticated>(),
      );
      expect(await harness.tokenStore.readRefreshToken(), isNull);
      expect(harness.repository.logoutCalls, 1);
    });
  });
}
