import 'package:fake_async/fake_async.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_riverpod/misc.dart' show Override;
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/auth/auth_notifier.dart';
import 'package:nebula_mobile/core/auth/auth_repository.dart';
import 'package:nebula_mobile/core/auth/auth_state.dart';
import 'package:nebula_mobile/core/auth/token_pair.dart';
import 'package:nebula_mobile/core/auth/user_principal.dart';
import 'package:nebula_mobile/core/hardware_id.dart';
import 'package:nebula_mobile/core/network/api_exception.dart';
import 'package:nebula_mobile/core/servers/server_repository.dart';
import 'package:nebula_mobile/core/storage/device_id_store.dart';
import 'package:nebula_mobile/core/storage/secure_token_store.dart';
import 'package:nebula_mobile/core/storage/storage_providers.dart';
import 'package:nebula_mobile/core/storage/xray_credential_store.dart';

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
  InMemoryXrayCredentialStore xrayCredentials,
})
_harness() {
  final FakeAuthRepository repository = FakeAuthRepository();
  final InMemorySecureTokenStore tokenStore = InMemorySecureTokenStore();
  final InMemoryDeviceIdStore deviceIdStore = InMemoryDeviceIdStore();
  final InMemoryXrayCredentialStore xrayCredentials =
      InMemoryXrayCredentialStore();

  final ProviderContainer container = ProviderContainer(
    overrides: <Override>[
      authRepositoryProvider.overrideWithValue(repository),
      secureTokenStoreProvider.overrideWithValue(tokenStore),
      deviceIdStoreProvider.overrideWithValue(deviceIdStore),
      xrayCredentialStoreProvider.overrideWithValue(xrayCredentials),
      hardwareIdProvider.overrideWithValue(() async => 'hardware-hash'),
    ],
  );

  return (
    container: container,
    repository: repository,
    tokenStore: tokenStore,
    deviceIdStore: deviceIdStore,
    xrayCredentials: xrayCredentials,
  );
}

void main() {
  group('AuthNotifier.bootstrap', () {
    test('with no stored refresh token lands unauthenticated', () async {
      final harness = _harness();
      addTearDown(harness.container.dispose);

      await harness.container.read(authNotifierProvider.notifier).bootstrap();

      expect(
        harness.container.read(authNotifierProvider),
        isA<AuthUnauthenticated>(),
      );
      expect(harness.repository.refreshCalls, 0);
    });

    test('with a stored refresh token that resolves lands authenticated and '
        'loads the principal', () async {
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

      await harness.container.read(authNotifierProvider.notifier).bootstrap();
      // Let the fire-and-forget `_loadMe` call resolve.
      await Future<void>.delayed(Duration.zero);

      final AuthState state = harness.container.read(authNotifierProvider);
      expect(state, isA<AuthAuthenticated>());
      final AuthAuthenticated authenticated = state as AuthAuthenticated;
      expect(authenticated.tokens.accessToken, 'fresh-access');
      expect(authenticated.me?.deviceId, 'device-1');
      expect(await harness.tokenStore.readRefreshToken(), 'rotated-refresh');
      expect(harness.deviceIdStore.read(), 'device-1');
    });

    test('with a stored refresh token that fails clears storage', () async {
      final harness = _harness();
      addTearDown(harness.container.dispose);
      await harness.tokenStore.writeRefreshToken('stale-refresh');
      harness.repository.refreshError = const NebulaApiException(
        statusCode: 401,
        detail: 'Authentication was not accepted',
      );

      await harness.container.read(authNotifierProvider.notifier).bootstrap();

      expect(
        harness.container.read(authNotifierProvider),
        isA<AuthUnauthenticated>(),
      );
      expect(await harness.tokenStore.readRefreshToken(), isNull);
    });
  });

  group('an unreachable server', () {
    // A stored session used to be deleted for any failure to resume it,
    // including not reaching the server at all. On a phone whose own tunnel
    // was up but carrying nothing, that signed the account out.
    Future<
      ({
        ProviderContainer container,
        FakeAuthRepository repository,
        InMemorySecureTokenStore tokenStore,
        InMemoryDeviceIdStore deviceIdStore,
        InMemoryXrayCredentialStore xrayCredentials,
      })
    >
    storedSession() async {
      final harness = _harness();
      addTearDown(harness.container.dispose);
      await harness.tokenStore.writeRefreshToken('stored-refresh');
      return harness;
    }

    test('keeps the session when nothing answers', () async {
      final harness = await storedSession();
      harness.repository.refreshError = const NebulaConnectivityException(
        'connection refused',
      );

      await harness.container.read(authNotifierProvider.notifier).bootstrap();

      expect(
        harness.container.read(authNotifierProvider),
        isA<AuthUnreachable>(),
      );
      expect(await harness.tokenStore.readRefreshToken(), 'stored-refresh');
    });

    test('keeps the session when the server is down', () async {
      final harness = await storedSession();
      harness.repository.refreshError = const NebulaApiException(
        statusCode: 503,
        detail: 'Authentication is temporarily unavailable',
      );

      await harness.container.read(authNotifierProvider.notifier).bootstrap();

      expect(
        harness.container.read(authNotifierProvider),
        isA<AuthUnreachable>(),
      );
      expect(await harness.tokenStore.readRefreshToken(), 'stored-refresh');
    });

    test('trying again resumes the session once the server answers', () async {
      final harness = await storedSession();
      final AuthNotifier notifier = harness.container.read(
        authNotifierProvider.notifier,
      );
      harness.repository.refreshError = const NebulaConnectivityException(
        'timeout',
      );
      await notifier.bootstrap();

      harness.repository.refreshError = null;
      harness.repository.refreshResult = () => _tokens(refresh: 'rotated');
      await notifier.retryRestore();

      expect(
        harness.container.read(authNotifierProvider),
        isA<AuthAuthenticated>(),
      );
      expect(await harness.tokenStore.readRefreshToken(), 'rotated');
    });

    test('keeps trying on its own, without anyone pressing anything', () {
      // The screen that used to hold the retry timer is gone: the app now
      // opens on its saved settings, so recovery cannot depend on somebody
      // sitting on a particular screen watching a spinner.
      fakeAsync((FakeAsync async) {
        ProviderContainer? container;
        FakeAuthRepository? repository;
        storedSession().then((
          ({
            ProviderContainer container,
            FakeAuthRepository repository,
            InMemorySecureTokenStore tokenStore,
            InMemoryDeviceIdStore deviceIdStore,
            InMemoryXrayCredentialStore xrayCredentials,
          })
          harness,
        ) {
          container = harness.container;
          repository = harness.repository;
        });
        async.flushMicrotasks();

        repository!.refreshError = const NebulaConnectivityException('timeout');
        container!.read(authNotifierProvider.notifier).bootstrap();
        async.flushMicrotasks();
        expect(container!.read(authNotifierProvider), isA<AuthUnreachable>());

        repository!.refreshError = null;
        repository!.refreshResult = () => _tokens(refresh: 'rotated');
        async.elapse(
          AuthNotifier.retryUnreachableAfter + const Duration(seconds: 1),
        );
        async.flushMicrotasks();

        expect(container!.read(authNotifierProvider), isA<AuthAuthenticated>());
      });
    });

    test('trying again signs out if the server then rejects it', () async {
      final harness = await storedSession();
      final AuthNotifier notifier = harness.container.read(
        authNotifierProvider.notifier,
      );
      harness.repository.refreshError = const NebulaConnectivityException(
        'timeout',
      );
      await notifier.bootstrap();

      harness.repository.refreshError = const NebulaApiException(
        statusCode: 401,
        detail: 'Authentication was not accepted',
      );
      await notifier.retryRestore();

      expect(
        harness.container.read(authNotifierProvider),
        isA<AuthUnauthenticated>(),
      );
      expect(await harness.tokenStore.readRefreshToken(), isNull);
    });

    test(
      'a refresh mid-session that cannot reach the server keeps it',
      () async {
        final harness = await storedSession();
        final AuthNotifier notifier = harness.container.read(
          authNotifierProvider.notifier,
        );
        harness.repository.refreshResult = () => _tokens(refresh: 'current');
        await notifier.bootstrap();

        harness.repository.refreshError = const NebulaConnectivityException(
          'connection refused',
        );
        await expectLater(
          notifier.refreshSession(),
          throwsA(isA<NebulaConnectivityException>()),
        );

        expect(
          harness.container.read(authNotifierProvider),
          isA<AuthAuthenticated>(),
        );
        expect(await harness.tokenStore.readRefreshToken(), 'current');
      },
    );
  });

  group('AuthNotifier.login', () {
    test('success transitions straight to authenticated', () async {
      final harness = _harness();
      addTearDown(harness.container.dispose);
      harness.repository.loginResult = () => _tokens();
      harness.repository.meResult = () =>
          const UserPrincipal(userId: 'u', sessionId: 's', deviceId: 'd');

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
      final AuthNotifier notifier = harness.container.read(
        authNotifierProvider.notifier,
      );
      // In the real app, the sign-in screen (and therefore login()) is only
      // reachable once bootstrap has already resolved to Unauthenticated --
      // reproduce that precondition rather than calling login() against a
      // freshly-built notifier still sitting in the default Authenticating
      // state.
      await notifier.bootstrap();
      expect(
        harness.container.read(authNotifierProvider),
        isA<AuthUnauthenticated>(),
      );

      harness.repository.loginError = const NebulaApiException(
        statusCode: 401,
        detail: 'Authentication was not accepted',
      );

      await expectLater(
        notifier.login(
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

    test(
      'a rejected remembered device is retried without its stale id',
      () async {
        final harness = _harness();
        addTearDown(harness.container.dispose);
        await harness.deviceIdStore.write('stale-device');
        await harness.container.read(authNotifierProvider.notifier).bootstrap();
        harness.repository.loginResult = () => _tokens();
        harness.repository.meResult = () => const UserPrincipal(
          userId: 'u',
          sessionId: 's',
          deviceId: 'fresh-device',
        );
        harness.repository.loginErrorForDeviceId = (String? deviceId) =>
            deviceId == 'stale-device'
            ? const NebulaApiException(
                statusCode: 401,
                detail: 'Authentication was not accepted',
              )
            : null;

        await harness.container
            .read(authNotifierProvider.notifier)
            .login(
              identifier: 'user@example.com',
              password: 'hunter22222222',
              deviceName: 'test device',
              platform: DevicePlatform.windows,
              clientVersion: '1.0.0',
            );

        expect(harness.repository.loginDeviceIds, <String?>[
          'stale-device',
          null,
        ]);
        // The reinstall match needs the hardware id on the retry too.
        expect(harness.repository.loginHardwareIds, <String?>[
          'hardware-hash',
          'hardware-hash',
        ]);
        expect(harness.deviceIdStore.read(), 'fresh-device');
      },
    );
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
    test(
      'always lands unauthenticated even if the network call fails',
      () async {
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
      },
    );

    test('forgets the tunnel credentials saved for offline use', () async {
      // The server revokes them on sign-out; a copy kept past it would raise
      // a tunnel that carries nothing, or one for the wrong account.
      final harness = _harness();
      addTearDown(harness.container.dispose);
      await harness.xrayCredentials.write(
        serverCode: 'ams-2',
        profileCode: 'vless-ws-tls',
        credential: const XrayClientResult(
          clientId: 'client',
          uuid: 'uuid',
          serverAddress: 'vpn.example.com',
          port: 8445,
          sni: 'vpn.example.com',
          transport: 'websocket',
          transportSecurity: 'tls',
          adBlock: false,
        ),
      );

      await harness.container.read(authNotifierProvider.notifier).logout();

      expect(harness.xrayCredentials.entries, isEmpty);
    });
  });
}
