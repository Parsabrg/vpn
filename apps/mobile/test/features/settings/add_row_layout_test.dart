import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_riverpod/misc.dart' show Override;
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/free/free_mode.dart';
import 'package:nebula_mobile/core/free/subscriptions.dart';
import 'package:nebula_mobile/core/storage/storage_providers.dart';
import 'package:nebula_mobile/features/free/free_mode_screen.dart';
import 'package:nebula_mobile/features/settings/bypass_domains_screen.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../../support/localised_app.dart';

/// A field with its Add button beside it, under the app's own theme.
///
/// The theme makes every filled button as wide as it is allowed to be, which
/// is right for the one action at the foot of a screen and wrong beside a
/// field: the button took the whole row, the field collapsed to nothing and
/// the button itself was not drawn. Seen in the Windows app; no test caught
/// it, because none looked at the sizes.
void main() {
  Future<void> expectRoom(WidgetTester tester, Widget screen) async {
    SharedPreferences.setMockInitialValues(<String, Object>{});
    final ProviderContainer container = ProviderContainer(
      overrides: <Override>[
        sharedPreferencesProvider.overrideWithValue(
          await SharedPreferences.getInstance(),
        ),
        freeLinkStoreProvider.overrideWithValue(InMemoryFreeLinkStore()),
        subscriptionStoreProvider.overrideWithValue(
          InMemorySubscriptionStore(),
        ),
      ],
    );
    addTearDown(container.dispose);
    await tester.pumpWidget(
      UncontrolledProviderScope(
        container: container,
        child: localisedApp(screen),
      ),
    );
    await tester.pumpAndSettle();

    // Every field-and-Add row on the screen: free mode has two, one for a
    // link and one for a subscription.
    final Finder fields = find.byType(TextField);
    final Finder buttons = find.widgetWithText(FilledButton, 'Add');
    expect(fields, findsWidgets);
    expect(buttons.evaluate().length, fields.evaluate().length);
    for (int i = 0; i < fields.evaluate().length; i++) {
      expect(tester.getSize(fields.at(i)).width, greaterThan(150));
      expect(tester.getSize(buttons.at(i)).width, inInclusiveRange(48, 160));
    }
    expect(tester.takeException(), isNull);
  }

  testWidgets('websites that skip the VPN', (WidgetTester tester) async {
    await expectRoom(tester, const BypassDomainsScreen());
  });

  testWidgets('a relay of your own', (WidgetTester tester) async {
    await expectRoom(tester, const FreeModeScreen());
  });
}
