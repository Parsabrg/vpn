import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_riverpod/misc.dart' show Override;
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:nebula_mobile/core/auth/auth_repository.dart';
import 'package:nebula_mobile/core/routing/route_paths.dart';
import 'package:nebula_mobile/core/storage/device_id_store.dart';
import 'package:nebula_mobile/core/storage/secure_token_store.dart';
import 'package:nebula_mobile/core/storage/storage_providers.dart';
import 'package:nebula_mobile/features/account_request/account_request_screen.dart';
import 'package:nebula_mobile/features/auth/sign_in_screen.dart';
import 'package:nebula_mobile/l10n/app_localizations.dart';

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
      GoRoute(
        path: RoutePaths.activate,
        builder: (BuildContext context, GoRouterState state) =>
            const Scaffold(body: Text('activate placeholder')),
      ),
    ],
  );

  return ProviderScope(
    overrides: <Override>[
      authRepositoryProvider.overrideWithValue(repository),
      secureTokenStoreProvider.overrideWithValue(InMemorySecureTokenStore()),
      deviceIdStoreProvider.overrideWithValue(InMemoryDeviceIdStore()),
    ],
    child: MaterialApp.router(
      routerConfig: router,
      localizationsDelegates: AppText.localizationsDelegates,
      supportedLocales: AppText.supportedLocales,
    ),
  );
}

void main() {
  testWidgets('the password visibility toggle has an accessible label', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(_harness(FakeAuthRepository()));

    // The icon shows the state: crossed out while the password is hidden.
    expect(find.bySemanticsLabel('Show password'), findsOneWidget);
    expect(find.byIcon(Icons.visibility_off_outlined), findsOneWidget);

    await tester.tap(find.bySemanticsLabel('Show password'));
    await tester.pump();

    expect(find.bySemanticsLabel('Hide password'), findsOneWidget);
    expect(find.byIcon(Icons.visibility_outlined), findsOneWidget);
  });

  testWidgets('rejects an empty submission without calling the API', (
    WidgetTester tester,
  ) async {
    final FakeAuthRepository repository = FakeAuthRepository();
    await tester.pumpWidget(_harness(repository));

    await tester.tap(find.widgetWithText(FilledButton, 'Continue'));
    await tester.pump();

    expect(find.text('Enter your email or username'), findsOneWidget);
    expect(repository.loginCalls, 0);
  });

  testWidgets('sign-in offers a way to reach activation', (
    WidgetTester tester,
  ) async {
    // The activation route existed and was registered, but nothing navigated
    // to it, so an approved user holding an activation code was stranded on a
    // form asking for a password they had never been able to set.
    await tester.pumpWidget(_harness(FakeAuthRepository()));

    await tester.tap(find.text('I have a code'));
    await tester.pumpAndSettle();

    expect(find.text('activate placeholder'), findsOneWidget);
  });

  testWidgets('the request screen has a way back to sign-in', (
    WidgetTester tester,
  ) async {
    // Seen on a phone: sign-in replaced itself with the request screen, which
    // then had no back arrow and nothing behind it to go back to.
    await tester.pumpWidget(_harness(FakeAuthRepository()));

    await tester.tap(find.text('Request access'));
    await tester.pumpAndSettle();
    await tester.tap(find.byIcon(Icons.arrow_back));
    await tester.pumpAndSettle();

    expect(find.byType(SignInScreen), findsOneWidget);
  });

  testWidgets('a sent request leads on to the activation code', (
    WidgetTester tester,
  ) async {
    // The sent state was an icon and a sentence with no way off it. What
    // comes next is the activation code the email carries.
    await tester.pumpWidget(_harness(FakeAuthRepository()));
    await tester.tap(find.text('Request access'));
    await tester.pumpAndSettle();
    await tester.enterText(
      find.byType(TextFormField).first,
      'user@example.com',
    );
    await tester.tap(find.widgetWithText(FilledButton, 'Send request'));
    await tester.pumpAndSettle();

    expect(find.text('Back to sign in'), findsOneWidget);
    await tester.tap(find.text('I have a code'));
    await tester.pumpAndSettle();

    expect(find.text('activate placeholder'), findsOneWidget);
  });
}
