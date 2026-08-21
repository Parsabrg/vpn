import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/storage/storage_providers.dart';
import 'package:nebula_mobile/core/theme/theme_mode_controller.dart';
import 'package:nebula_mobile/features/settings/settings_screen.dart';
import 'package:shared_preferences/shared_preferences.dart';

Future<ProviderContainer> _containerWithPreferences() async {
  SharedPreferences.setMockInitialValues(<String, Object>{});
  final SharedPreferences preferences = await SharedPreferences.getInstance();
  return ProviderContainer(
    overrides: <Override>[
      sharedPreferencesProvider.overrideWithValue(preferences),
    ],
  );
}

void main() {
  testWidgets('selecting a theme mode updates and persists state', (
    WidgetTester tester,
  ) async {
    final ProviderContainer container = await _containerWithPreferences();
    addTearDown(container.dispose);

    await tester.pumpWidget(
      UncontrolledProviderScope(
        container: container,
        child: const MaterialApp(home: SettingsScreen()),
      ),
    );

    expect(container.read(themeModeProvider), ThemeMode.system);

    await tester.tap(find.text('Dark'));
    await tester.pumpAndSettle();

    expect(container.read(themeModeProvider), ThemeMode.dark);
  });

  testWidgets('the theme control is reachable by its semantics label', (
    WidgetTester tester,
  ) async {
    final ProviderContainer container = await _containerWithPreferences();
    addTearDown(container.dispose);

    await tester.pumpWidget(
      UncontrolledProviderScope(
        container: container,
        child: const MaterialApp(home: SettingsScreen()),
      ),
    );

    expect(find.bySemanticsLabel('Theme mode'), findsOneWidget);
  });
}
