/// The sanctioned-services list is data Xray parses at connect time.
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/routing/sanctioned_domains.dart';

void main() {
  test('every entry is a domain rule Xray accepts', () {
    // A bare name is not a Xray domain rule, and a malformed rule fails the
    // whole config, which takes the tunnel down rather than skipping an entry.
    final RegExp rule = RegExp('^domain:[a-z0-9-]+(\\.[a-z0-9-]+)+\$');
    for (final String entry in sanctionedDomains) {
      expect(rule.hasMatch(entry), isTrue, reason: entry);
    }
  });

  test('no entry is listed twice', () {
    expect(sanctionedDomains.toSet().length, sanctionedDomains.length);
  });

  test('no entry is already covered by a broader one', () {
    // `domain:` matches subdomains, so a name under another listed name is
    // dead weight in every connection's rule check.
    final List<String> names = <String>[
      for (final String entry in sanctionedDomains)
        entry.substring('domain:'.length),
    ];
    for (final String name in names) {
      for (final String other in names) {
        if (name != other) {
          expect(name.endsWith('.$other'), isFalse, reason: name);
        }
      }
    }
  });
}
