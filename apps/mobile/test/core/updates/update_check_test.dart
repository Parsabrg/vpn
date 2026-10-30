import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_riverpod/misc.dart' show Override;
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/storage/storage_providers.dart';
import 'package:nebula_mobile/core/updates/update_check.dart';
import 'package:shared_preferences/shared_preferences.dart';

class _FakeReleases implements ReleaseSource {
  _FakeReleases(this.release);

  final Map<String, dynamic>? release;
  int calls = 0;

  @override
  Future<Map<String, dynamic>?> latest() async {
    calls++;
    return release;
  }
}

Map<String, dynamic> _release(String tag, {bool prerelease = false}) {
  return <String, dynamic>{
    'tag_name': tag,
    'html_url': 'https://github.com/Parsabrg/vpn/releases/tag/$tag',
    'draft': false,
    'prerelease': prerelease,
  };
}

Future<ProviderContainer> _container({
  required String? installed,
  required _FakeReleases releases,
  bool? checksEnabled,
}) async {
  SharedPreferences.setMockInitialValues(<String, Object>{
    'nebula.check_for_updates': ?checksEnabled,
  });
  final SharedPreferences preferences = await SharedPreferences.getInstance();
  return ProviderContainer(
    overrides: <Override>[
      sharedPreferencesProvider.overrideWithValue(preferences),
      installedVersionProvider.overrideWith((Ref ref) async => installed),
      releaseSourceProvider.overrideWithValue(releases),
    ],
  );
}

void main() {
  group('comparing versions', () {
    test('by number, not by text', () {
      expect(compareVersions('0.1.10', '0.1.9'), greaterThan(0));
      expect(compareVersions('v0.2.0', '0.1.6'), greaterThan(0));
      expect(compareVersions('0.1.6', '0.1.6'), 0);
      expect(compareVersions('0.1', '0.1.0'), 0);
      expect(compareVersions('0.1.5', 'v0.1.6'), lessThan(0));
    });

    test('ignores build numbers and pre-release labels', () {
      expect(compareVersions('0.1.6+7', '0.1.6'), 0);
      expect(compareVersions('0.1.7-rc.1', '0.1.6'), greaterThan(0));
    });

    test('is no answer for something that is not a version', () {
      expect(compareVersions('dev', '0.1.6'), isNull);
      expect(compareVersions('', '0.1.6'), isNull);
    });
  });

  group('what a release offers', () {
    test('a newer release is an update', () {
      final AvailableUpdate? update = updateFromRelease(
        _release('v0.1.7'),
        '0.1.6',
      );
      expect(update?.version, '0.1.7');
      expect(update?.page.host, 'github.com');
    });

    test('the same or an older release is not', () {
      expect(updateFromRelease(_release('v0.1.6'), '0.1.6'), isNull);
      expect(updateFromRelease(_release('v0.1.5'), '0.1.6'), isNull);
    });

    test('pre-releases and drafts are not offered', () {
      expect(
        updateFromRelease(_release('v0.2.0', prerelease: true), '0.1.6'),
        isNull,
      );
      expect(
        updateFromRelease(_release('v0.2.0')..['draft'] = true, '0.1.6'),
        isNull,
      );
    });

    test('a page anywhere but github.com over https is not opened', () {
      expect(
        updateFromRelease(
          _release('v0.2.0')..['html_url'] = 'https://example.com/nebula.apk',
          '0.1.6',
        ),
        isNull,
      );
      expect(
        updateFromRelease(
          _release('v0.2.0')
            ..['html_url'] = 'http://github.com/Parsabrg/vpn/releases',
          '0.1.6',
        ),
        isNull,
      );
    });
  });

  group('the check', () {
    test('offers a newer release', () async {
      final _FakeReleases releases = _FakeReleases(_release('v0.1.7'));
      final ProviderContainer container = await _container(
        installed: '0.1.6',
        releases: releases,
      );
      addTearDown(container.dispose);

      final AvailableUpdate? update = await container.read(
        availableUpdateProvider.future,
      );

      expect(update?.version, '0.1.7');
    });

    test('asks nobody when it is turned off', () async {
      final _FakeReleases releases = _FakeReleases(_release('v0.1.7'));
      final ProviderContainer container = await _container(
        installed: '0.1.6',
        releases: releases,
        checksEnabled: false,
      );
      addTearDown(container.dispose);

      expect(await container.read(availableUpdateProvider.future), isNull);
      expect(releases.calls, 0);
    });

    test('asks nobody for a build with no version', () async {
      final _FakeReleases releases = _FakeReleases(_release('v0.1.7'));
      final ProviderContainer container = await _container(
        installed: null,
        releases: releases,
      );
      addTearDown(container.dispose);

      expect(await container.read(availableUpdateProvider.future), isNull);
      expect(releases.calls, 0);
    });

    test('finds nothing when nothing is published', () async {
      // A private repository, no network, or a rate limit all look like this.
      final ProviderContainer container = await _container(
        installed: '0.1.6',
        releases: _FakeReleases(null),
      );
      addTearDown(container.dispose);

      expect(await container.read(availableUpdateProvider.future), isNull);
    });
  });
}
