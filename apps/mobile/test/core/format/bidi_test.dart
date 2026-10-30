/// Left-to-right values on a right-to-left screen.
library;

import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/format/bidi.dart';

void main() {
  group('inherentDirection', () {
    test('a value with no right-to-left letters reads left to right', () {
      for (final String value in <String>[
        '8.9 KB',
        '612 / 1024 GB',
        'vless-xhttp-tls-adblock',
        'owner@example.org',
        '123 ms',
      ]) {
        expect(inherentDirection(value), TextDirection.ltr, reason: value);
      }
    });

    test('a translated phrase keeps the direction of the screen', () {
      // Persian for "no expiry" and "active".
      expect(
        inherentDirection(
          '\u0628\u062F\u0648\u0646 \u0627\u0646\u0642\u0636\u0627',
        ),
        isNull,
      );
      expect(inherentDirection('\u0641\u0639\u0627\u0644'), isNull);
    });
  });

  testWidgets('a value is fenced off only in a right-to-left layout', (
    WidgetTester tester,
  ) async {
    late String inRtl;
    late String inLtr;
    await tester.pumpWidget(
      Directionality(
        textDirection: TextDirection.rtl,
        child: Builder(
          builder: (BuildContext context) {
            inRtl = embedLeftToRight(context, '8.9 KB');
            return const SizedBox();
          },
        ),
      ),
    );
    await tester.pumpWidget(
      Directionality(
        textDirection: TextDirection.ltr,
        child: Builder(
          builder: (BuildContext context) {
            inLtr = embedLeftToRight(context, '8.9 KB');
            return const SizedBox();
          },
        ),
      ),
    );

    // Untouched in English, so existing copy and tests match exactly.
    expect(inLtr, '8.9 KB');
    // Isolated in Persian, so it is not reordered into "KB 8.9".
    expect(inRtl, '\u20668.9 KB\u2069');
  });
}
