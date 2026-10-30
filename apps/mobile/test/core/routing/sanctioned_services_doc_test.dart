/// The published list and the app's list are the same list.
library;

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/routing/sanctioned_domains.dart';

void main() {
  test(
    'docs/sanctioned-services.md lists exactly the domains the app routes',
    () {
      // The doc is what other Xray clients are set up from. If the two
      // drift, the app and that client quietly disagree about which services
      // work, and nothing else would notice.
      final String doc = File(
        '../../docs/sanctioned-services.md',
      ).readAsStringSync();
      final List<String> inDoc = RegExp(
        r'"(domain:[^"]+)"',
      ).allMatches(doc).map((RegExpMatch m) => m.group(1)!).toSet().toList();

      expect(inDoc.toSet(), sanctionedDomains.toSet());
      // By line rather than by searching for "\n...\n", so a checkout with
      // Windows line endings does not fail a list that is correct.
      final Set<String> lines = doc
          .split(RegExp(r'\r?\n'))
          .map((String line) => line.trim())
          .toSet();
      for (final String domain in sanctionedDomains) {
        expect(
          lines.contains(domain),
          isTrue,
          reason: 'one-per-line list is missing $domain',
        );
      }
    },
  );
}
