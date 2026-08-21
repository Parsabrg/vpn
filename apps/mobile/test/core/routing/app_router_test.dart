import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:nebula_mobile/core/auth/auth_notifier.dart';
import 'package:nebula_mobile/core/auth/auth_state.dart';
import 'package:nebula_mobile/core/auth/token_pair.dart';
import 'package:nebula_mobile/core/routing/app_router.dart';
import 'package:nebula_mobile/core/routing/route_paths.dart';
import 'package:nebula_mobile/core/storage/storage_providers.dart';
import 'package:nebula_mobile/features/account_request/account_request_screen.dart';
import 'package:nebula_mobile/features/auth/sign_in_screen.dart';
import 'package:nebula_mobile/features/devices/devices_placeholder_screen.dart';
import 'package:nebula_mobile/features/splash/splash_screen.dart';
import 'package:shared_preferences/shared_preferences.dart';

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

const TokenPair _authenticatedTokens = TokenPair(
  accessToken: 'access',
  refreshToken: 'refresh',
  expiresIn: Duration(minutes: 15),
);

Future<ProviderContainer> _containerWith(AuthState initial) async {
  SharedPreferences.setMockInitialValues(<String, Object>{});
  final SharedPreferences preferences = await SharedPreferences.getInstance();
  return ProviderContainer(
    overrides: <Override>[
      sharedPreferencesProvider.overrideWithValue(preferences),
      authNotifierProvider.overrideWith(() => _TestAuthNotifier(initial)),
    ],
  );
}

Widget _appFor(ProviderContainer container) {
  return UncontrolledProviderScope(
    container: container,
    child: MaterialApp.router(routerConfig: container.read(routerProvider)),
  );
}

void main() {
  testWidgets('renders the splash screen while bootstrap is in progress', (
    WidgetTester tester,
  ) async {
    final ProviderContainer container = await _containerWith(
      const AuthAuthenticating(),
    );
    addTearDown(container.dispose);

    await tester.pumpWidget(_appFor(container));
    await tester.pumpAndSettle();

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

    expect(find.byType(DevicesPlaceholderScreen), findsOneWidget);
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
    expect(find.byType(DevicesPlaceholderScreen), findsOneWidget);

    final _TestAuthNotifier notifier =
        container.read(authNotifierProvider.notifier) as _TestAuthNotifier;
    notifier.emit(const AuthSessionExpired());
    await tester.pumpAndSettle();

    expect(find.byType(SignInScreen), findsOneWidget);
  });
}
