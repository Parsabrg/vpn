import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/storage/secure_token_store.dart';
import 'package:nebula_mobile/core/storage/storage_providers.dart';
import 'package:nebula_mobile/features/splash/splash_screen.dart';
import 'package:nebula_mobile/src/nebula_app.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  testWidgets('boots to the splash screen while auth state resolves', (
    WidgetTester tester,
  ) async {
    // Phase 1.1's placeholder shell is gone -- the app now wires theming,
    // routing, and auth state together for real (see PROJECT_PROGRESS.md
    // Phase 1.7a). This is the smoke test proving that wiring doesn't
    // crash on first frame; behavior for each auth state is covered by
    // `test/core/routing/app_router_test.dart`.
    SharedPreferences.setMockInitialValues(<String, Object>{});
    final SharedPreferences preferences =
        await SharedPreferences.getInstance();

    await tester.pumpWidget(
      ProviderScope(
        overrides: <Override>[
          sharedPreferencesProvider.overrideWithValue(preferences),
          secureTokenStoreProvider.overrideWithValue(
            InMemorySecureTokenStore(),
          ),
        ],
        child: const NebulaApp(),
      ),
    );
    await tester.pump();

    expect(find.byType(SplashScreen), findsOneWidget);
  });
}
