import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_riverpod/misc.dart' show Override;
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:nebula_mobile/core/auth/auth_notifier.dart';
import 'package:nebula_mobile/core/auth/auth_state.dart';
import 'package:nebula_mobile/core/auth/token_pair.dart';
import 'package:nebula_mobile/core/free/free_mode.dart';
import 'package:nebula_mobile/core/free/subscriptions.dart';
import 'package:nebula_mobile/core/pairing/pairing.dart';
import 'package:nebula_mobile/core/pairing/pairing_providers.dart';
import 'package:nebula_mobile/core/pairing/pairing_store.dart';
import 'package:nebula_mobile/core/routing/app_router.dart';
import 'package:nebula_mobile/core/routing/route_paths.dart';
import 'package:nebula_mobile/core/servers/server_repository.dart';
import 'package:nebula_mobile/core/storage/secure_token_store.dart';
import 'package:nebula_mobile/core/storage/storage_providers.dart';
import 'package:nebula_mobile/core/wireguard/tunnel_controller.dart';
import 'package:nebula_mobile/features/account_request/account_request_screen.dart';
import 'package:nebula_mobile/features/auth/sign_in_screen.dart';
import 'package:nebula_mobile/features/connect/connect_screen.dart';
import 'package:nebula_mobile/features/free/free_mode_screen.dart';
import 'package:nebula_mobile/features/pairing/pairing_screen.dart';
import 'package:nebula_mobile/features/splash/splash_screen.dart';
import 'package:nebula_mobile/l10n/app_localizations.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../../features/devices/fake_tunnel_controller.dart';

/// Bypasses the real repository/storage-backed [AuthNotifier.build] so this
/// test can force whichever [AuthState] the redirect table under test
/// needs, without wiring an API client.
class _TestAuthNotifier extends AuthNotifier {
  _TestAuthNotifier(this._initial);

  final AuthState _initial;

  @override
  AuthState build() => _initial;

  void emit(AuthState next) => state = next;
}

/// Avoids DevicesScreen's initState firing a real network call against
/// dioProvider's base URL, which this router-level test has no interest in
/// exercising.
class _FakeServerRepository implements ServerRepository {
  @override
  Future<List<AvailableServer>> listAvailableServers() async =>
      <AvailableServer>[];

  @override
  Future<WireGuardPeerResult> requestPeer({
    required String deviceId,
    required String serverCode,
    required String protocolProfileCode,
    required String publicKey,
  }) => throw UnimplementedError();

  @override
  Future<void> revokePeer({
    required String deviceId,
    required String serverCode,
  }) => throw UnimplementedError();

  @override
  Future<XrayClientResult> requestXrayClient({
    required String deviceId,
    required String serverCode,
    required String protocolProfileCode,
  }) => throw UnimplementedError();

  @override
  Future<void> revokeXrayClient({
    required String deviceId,
    required String serverCode,
    required String protocolProfileCode,
  }) => throw UnimplementedError();
}

const TokenPair _authenticatedTokens = TokenPair(
  accessToken: 'access',
  refreshToken: 'refresh',
  expiresIn: Duration(minutes: 15),
);

Future<ProviderContainer> _containerWith(
  AuthState initial, {
  TunnelController? tunnel,
  bool unpaired = false,
  Pairing? stored,
}) async {
  SharedPreferences.setMockInitialValues(<String, Object>{});
  final SharedPreferences preferences = await SharedPreferences.getInstance();
  return ProviderContainer(
    overrides: <Override>[
      sharedPreferencesProvider.overrideWithValue(preferences),
      authNotifierProvider.overrideWith(() => _TestAuthNotifier(initial)),
      serverRepositoryProvider.overrideWithValue(_FakeServerRepository()),
      if (tunnel != null) tunnelControllerProvider.overrideWithValue(tunnel),
      pairingStoreProvider.overrideWithValue(InMemoryPairingStore(stored)),
      secureTokenStoreProvider.overrideWithValue(InMemorySecureTokenStore()),
      // Secure storage otherwise, which is a platform channel here.
      freeLinkStoreProvider.overrideWithValue(InMemoryFreeLinkStore()),
      subscriptionStoreProvider.overrideWithValue(InMemorySubscriptionStore()),
      storedPairingProvider.overrideWithValue(stored),
      if (unpaired) pairingProvider.overrideWith(_UnpairedNotifier.new),
    ],
  );
}

/// A generic release build: no address of its own and nothing stored.
class _UnpairedNotifier extends PairingNotifier {
  @override
  Pairing? build() => null;
}

Widget _appFor(ProviderContainer container) {
  return UncontrolledProviderScope(
    container: container,
    child: MaterialApp.router(
      routerConfig: container.read(routerProvider),
      // The screens read their copy through AppText, which needs these.
      localizationsDelegates: AppText.localizationsDelegates,
      supportedLocales: AppText.supportedLocales,
    ),
  );
}

void main() {
  group('with no server', () {
    testWidgets('the first page lets someone in without one, and back out', (
      WidgetTester tester,
    ) async {
      final ProviderContainer container = await _containerWith(
        const AuthUnauthenticated(),
        unpaired: true,
        tunnel: FakeTunnelController(),
      );
      addTearDown(container.dispose);
      await tester.pumpWidget(_appFor(container));
      await tester.pumpAndSettle();
      expect(find.byType(PairingScreen), findsOneWidget);

      await tester.tap(find.text("I don't have a server"));
      await tester.pumpAndSettle();

      // Straight to the connect screen: nothing to pair with or sign in to.
      expect(find.byType(ConnectScreen), findsOneWidget);
      // No devices to list without an account; the third tab is the relays.
      expect(find.text('Devices'), findsNothing);
      await tester.tap(find.text('Free'));
      await tester.pumpAndSettle();
      expect(find.byType(FreeModeScreen), findsOneWidget);

      // The door screens lead back in while this is on.
      container.read(routerProvider).go(RoutePaths.signIn);
      await tester.pumpAndSettle();
      expect(find.byType(SignInScreen), findsNothing);

      container.read(routerProvider).go(RoutePaths.homeAccount);
      await tester.pumpAndSettle();
      await tester.tap(find.text('I have a server'));
      await tester.pumpAndSettle();
      expect(find.byType(PairingScreen), findsOneWidget);
      expect(container.read(freeModeProvider), isFalse);
    });

    testWidgets('a relay of their own is added and removed', (
      WidgetTester tester,
    ) async {
      final ProviderContainer container = await _containerWith(
        const AuthUnauthenticated(),
        unpaired: true,
        tunnel: FakeTunnelController(),
      );
      addTearDown(container.dispose);
      await container.read(freeModeProvider.notifier).enter();
      await tester.pumpWidget(_appFor(container));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Free'));
      await tester.pumpAndSettle();
      // This build was given no relay of its own.
      expect(
        find.text('This app came with no relay. Add your own below.'),
        findsOneWidget,
      );

      // The link field is the first; the second is for subscriptions.
      await tester.enterText(
        find.byType(TextField).first,
        'https://example.com',
      );
      await tester.tap(find.text('Add').first);
      await tester.pumpAndSettle();
      expect(find.textContaining('This link cannot be used'), findsOneWidget);

      await tester.enterText(
        find.byType(TextField).first,
        'vless://0f1e2d3c-4b5a-4978-8a6b-5c4d3e2f1a0b@188.114.97.6:443'
        '?security=tls&type=ws&sni=mine.example.workers.dev#Mine',
      );
      await tester.tap(find.text('Add').first);
      await tester.pumpAndSettle();
      expect(find.text('Mine'), findsOneWidget);
      expect(find.text('added by you'), findsOneWidget);
      expect(find.textContaining('This link cannot be used'), findsNothing);

      await tester.tap(find.byTooltip('Remove'));
      await tester.pumpAndSettle();
      expect(find.text('Mine'), findsNothing);
    });
  });

  group('a generic build that has not been paired', () {
    testWidgets('asks for a pairing link before anything else', (
      WidgetTester tester,
    ) async {
      final ProviderContainer container = await _containerWith(
        const AuthUnauthenticated(),
        unpaired: true,
      );
      addTearDown(container.dispose);

      await tester.pumpWidget(_appFor(container));
      container.read(routerProvider).go(RoutePaths.signIn);
      await tester.pumpAndSettle();

      expect(find.byType(PairingScreen), findsOneWidget);
      expect(find.byType(SignInScreen), findsNothing);
    });

    testWidgets('then signs in to the deployment it paired with, and can '
        'change it', (WidgetTester tester) async {
      final ProviderContainer container = await _containerWith(
        const AuthUnauthenticated(),
        unpaired: true,
      );
      addTearDown(container.dispose);
      await tester.pumpWidget(_appFor(container));
      await tester.pumpAndSettle();

      await container
          .read(pairingProvider.notifier)
          .adopt(
            const Pairing(
              apiUrl: 'https://vpn.example.org',
              deploymentId: '7d3c1f2e-0b5a-4c9d-8e61-2f4a9b0c1d2e',
              deploymentName: 'Home',
              caCertificatePem: null,
              caSha256: null,
              profiles: <String>['wireguard-native'],
            ),
          );
      container.read(routerProvider).go(RoutePaths.signIn);
      await tester.pumpAndSettle();

      expect(find.byType(SignInScreen), findsOneWidget);
      expect(find.text('Server: Home'), findsOneWidget);
      expect(
        await container.read(pairingStoreProvider).read(),
        isNotNull,
        reason: 'kept for the next launch',
      );

      await tester.tap(find.text('Change server'));
      await tester.pumpAndSettle();

      expect(find.byType(PairingScreen), findsOneWidget);
      expect(await container.read(pairingStoreProvider).read(), isNull);
    });
  });

  group('a server that could not be reached', () {
    testWidgets('opens the app on saved settings, not a wall', (
      WidgetTester tester,
    ) async {
      // This used to stop at the splash with a Try again button. On a
      // blocked address the server never answers, and the tunnel -- the one
      // thing that could reach it again -- was behind that screen.
      //
      // Explicitly no tunnel, rather than letting the real controller stand
      // in: on Windows that one answers `activeVpn` by shelling out to check
      // the adapter, and a process started inside a widget test is a pending
      // timer the test then fails on.
      final ProviderContainer container = await _containerWith(
        const AuthUnreachable(),
        tunnel: FakeTunnelController(),
      );
      addTearDown(container.dispose);

      await tester.pumpWidget(_appFor(container));
      await tester.pumpAndSettle();

      expect(find.byType(ConnectScreen), findsOneWidget);
      expect(find.byType(SplashScreen), findsNothing);
      expect(find.byType(SignInScreen), findsNothing);
    });

    testWidgets('and sign-in is not where an unreachable session belongs', (
      WidgetTester tester,
    ) async {
      final ProviderContainer container = await _containerWith(
        const AuthUnreachable(),
        tunnel: FakeTunnelController(),
      );
      addTearDown(container.dispose);

      await tester.pumpWidget(_appFor(container));
      container.read(routerProvider).go(RoutePaths.signIn);
      await tester.pumpAndSettle();

      expect(find.byType(SignInScreen), findsNothing);
      expect(find.byType(ConnectScreen), findsOneWidget);
    });
  });

  testWidgets('renders the splash screen while bootstrap is in progress', (
    WidgetTester tester,
  ) async {
    final ProviderContainer container = await _containerWith(
      const AuthAuthenticating(),
    );
    addTearDown(container.dispose);

    await tester.pumpWidget(_appFor(container));
    // Not pumpAndSettle: the splash screen's CircularProgressIndicator
    // animates indefinitely by design (bootstrap has no fixed duration), so
    // it never "settles" -- a single pump is enough to resolve the initial
    // route and render the screen.
    await tester.pump();

    expect(find.byType(SplashScreen), findsOneWidget);
  });

  testWidgets('redirects an unauthenticated user to sign-in', (
    WidgetTester tester,
  ) async {
    final ProviderContainer container = await _containerWith(
      const AuthUnauthenticated(),
    );
    addTearDown(container.dispose);

    await tester.pumpWidget(_appFor(container));
    await tester.pumpAndSettle();

    expect(find.byType(SignInScreen), findsOneWidget);
  });

  testWidgets('leaves account-request reachable while unauthenticated', (
    WidgetTester tester,
  ) async {
    final ProviderContainer container = await _containerWith(
      const AuthUnauthenticated(),
    );
    addTearDown(container.dispose);
    final GoRouter router = container.read(routerProvider);

    await tester.pumpWidget(_appFor(container));
    await tester.pumpAndSettle();

    router.go(RoutePaths.accountRequest);
    await tester.pumpAndSettle();

    expect(find.byType(AccountRequestScreen), findsOneWidget);
  });

  testWidgets('lands an authenticated user on the home shell', (
    WidgetTester tester,
  ) async {
    final ProviderContainer container = await _containerWith(
      const AuthAuthenticated(tokens: _authenticatedTokens),
    );
    addTearDown(container.dispose);

    await tester.pumpWidget(_appFor(container));
    await tester.pumpAndSettle();

    expect(find.byType(ConnectScreen), findsOneWidget);
  });

  testWidgets('the tab bar keeps its full height above 3-button navigation', (
    WidgetTester tester,
  ) async {
    // A 48px bottom inset is what 3-button navigation reserves. The bar used
    // to take the inset out of its own 60px and squeeze the icons to 12px.
    tester.view
      ..devicePixelRatio = 1
      ..physicalSize = const Size(400, 800)
      ..padding = const FakeViewPadding(bottom: 48)
      ..viewPadding = const FakeViewPadding(bottom: 48);
    addTearDown(tester.view.reset);
    final ProviderContainer container = await _containerWith(
      const AuthAuthenticated(tokens: _authenticatedTokens),
      tunnel: FakeTunnelController(),
    );
    addTearDown(container.dispose);

    await tester.pumpWidget(_appFor(container));
    await tester.pumpAndSettle();

    final Rect icon = tester.getRect(find.byIcon(Icons.shield));
    expect(icon.height, 20);
    expect(icon.bottom, lessThanOrEqualTo(800 - 48));
  });

  testWidgets('a live session-expiry bounces the user back to sign-in', (
    WidgetTester tester,
  ) async {
    final ProviderContainer container = await _containerWith(
      const AuthAuthenticated(tokens: _authenticatedTokens),
    );
    addTearDown(container.dispose);

    await tester.pumpWidget(_appFor(container));
    await tester.pumpAndSettle();
    expect(find.byType(ConnectScreen), findsOneWidget);

    final _TestAuthNotifier notifier =
        container.read(authNotifierProvider.notifier) as _TestAuthNotifier;
    notifier.emit(const AuthSessionExpired());
    await tester.pumpAndSettle();

    expect(find.byType(SignInScreen), findsOneWidget);
  });
}
