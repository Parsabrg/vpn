import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:nebula_mobile/core/auth/auth_repository.dart';
import 'package:nebula_mobile/core/routing/route_paths.dart';
import 'package:nebula_mobile/core/storage/device_id_store.dart';
import 'package:nebula_mobile/core/storage/secure_token_store.dart';
import 'package:nebula_mobile/core/storage/storage_providers.dart';
import 'package:nebula_mobile/features/account_request/account_request_screen.dart';
import 'package:nebula_mobile/features/auth/sign_in_screen.dart';

import '../../core/auth/fake_auth_repository.dart';

Widget _harness(FakeAuthRepository repository) {
  final GoRouter router = GoRouter(
    initialLocation: RoutePaths.signIn,
    routes: <RouteBase>[
      GoRoute(
        path: RoutePaths.signIn,
        builder: (BuildContext context, GoRouterState state) =>
            const SignInScreen(),
      ),
      GoRoute(
        path: RoutePaths.accountRequest,
        builder: (BuildContext context, GoRouterState state) =>
            const AccountRequestScreen(),
      ),
      GoRoute(
        path: RoutePaths.passwordReset,
        builder: (BuildContext context, GoRouterState state) =>
            const Scaffold(body: Text('reset placeholder')),
      ),
    ],
  );

  return ProviderScope(
    overrides: <Override>[
      authRepositoryProvider.overrideWithValue(repository),
      secureTokenStoreProvider.overrideWithValue(InMemorySecureTokenStore()),
      deviceIdStoreProvider.overrideWithValue(InMemoryDeviceIdStore()),
    ],
    child: MaterialApp.router(routerConfig: router),
  );
}

void main() {
  testWidgets('the password visibility toggle has an accessible label', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(_harness(FakeAuthRepository()));

    expect(find.bySemanticsLabel('Show password'), findsOneWidget);

    await tester.tap(find.bySemanticsLabel('Show password'));
    await tester.pump();

    expect(find.bySemanticsLabel('Hide password'), findsOneWidget);
  });

  testWidgets('rejects an empty submission without calling the API', (
    WidgetTester tester,
  ) async {
    final FakeAuthRepository repository = FakeAuthRepository();
    await tester.pumpWidget(_harness(repository));

    await tester.tap(find.widgetWithText(FilledButton, 'Sign in'));
    await tester.pump();

    expect(find.text('Enter your email or username'), findsOneWidget);
    expect(repository.loginCalls, 0);
  });
}
