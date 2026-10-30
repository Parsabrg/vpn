/// Capitals in the language on screen.
library;

import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/format/case.dart';

import '../../support/localised_app.dart';

Future<String> _upper(WidgetTester tester, String language, String text) async {
  late String result;
  await tester.pumpWidget(
    localisedApp(
      Builder(
        builder: (BuildContext context) {
          result = upperCaseFor(context, text);
          return const SizedBox();
        },
      ),
      locale: Locale(language),
    ),
  );
  return result;
}

void main() {
  testWidgets('Turkish capitalises a dotted i to a dotted capital', (
    WidgetTester tester,
  ) async {
    // "Bağlı değil" is "not connected"; with a plain capital I the second word
    // is misspelt.
    expect(await _upper(tester, 'tr', 'bağlı değil'), 'BAĞLI DEĞİL');
  });

  testWidgets('every other language capitalises as it always did', (
    WidgetTester tester,
  ) async {
    expect(await _upper(tester, 'en', 'disconnected'), 'DISCONNECTED');
    expect(await _upper(tester, 'de', 'getrennt'), 'GETRENNT');
  });
}
