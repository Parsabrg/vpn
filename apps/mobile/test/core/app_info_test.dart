import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/app_info.dart';

void main() {
  test('kClientVersion matches the version in pubspec.yaml', () {
    // The constant is kept in sync by hand, and was not: it sat at 0.1.0
    // through four releases while its own comment claimed otherwise, so every
    // sign-in reported a version the app had not been for months. Since it is
    // what the API records per session, drift there is silently misleading
    // rather than obviously broken -- exactly the kind of thing that needs a
    // test rather than a comment.
    final File pubspec = File('pubspec.yaml');
    expect(
      pubspec.existsSync(),
      isTrue,
      reason: 'run from apps/mobile so the relative path resolves',
    );

    final String versionLine = pubspec.readAsLinesSync().firstWhere(
      (String line) => line.startsWith('version:'),
      orElse: () => '',
    );
    expect(versionLine, isNotEmpty, reason: 'pubspec.yaml has no version:');

    // `version: 0.1.5+6` -- the build number after `+` is Android's
    // versionCode and is deliberately not part of the reported version.
    final String declared = versionLine.split(':')[1].trim().split('+').first;

    expect(
      kClientVersion,
      declared,
      reason:
          'kClientVersion is $kClientVersion but pubspec.yaml says $declared. '
          'Bump both together, or the API records the wrong client version.',
    );
  });
}
