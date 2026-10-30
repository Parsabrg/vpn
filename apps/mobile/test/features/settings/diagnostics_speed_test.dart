import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_riverpod/misc.dart' show Override;
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/diagnostics/speed_test.dart';
import 'package:nebula_mobile/core/storage/storage_providers.dart';
import 'package:nebula_mobile/features/settings/diagnostics_screen.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../../support/localised_app.dart';

class _FixedSpeedTest extends SpeedTest {
  @override
  Future<SpeedReport> run() async => (downloadMbps: 86.4, uploadMbps: null);
}

void main() {
  testWidgets('a speed test shows each way, and says what it could not get', (
    WidgetTester tester,
  ) async {
    SharedPreferences.setMockInitialValues(<String, Object>{});
    final ProviderContainer container = ProviderContainer(
      overrides: <Override>[
        sharedPreferencesProvider.overrideWithValue(
          await SharedPreferences.getInstance(),
        ),
        speedTestProvider.overrideWithValue(_FixedSpeedTest()),
      ],
    );
    addTearDown(container.dispose);
    await tester.pumpWidget(
      UncontrolledProviderScope(
        container: container,
        child: localisedApp(const DiagnosticsScreen()),
      ),
    );
    await tester.pumpAndSettle();

    final Finder list = find.byType(Scrollable).first;
    await tester.scrollUntilVisible(
      find.text('Run speed test'),
      200,
      scrollable: list,
    );
    await tester.tap(find.text('Run speed test'));
    await tester.pumpAndSettle();
    await tester.scrollUntilVisible(find.text('Upload'), 200, scrollable: list);

    expect(find.text('86 Mbps'), findsOneWidget);
    expect(find.text('Could not measure'), findsOneWidget);
  });
}
