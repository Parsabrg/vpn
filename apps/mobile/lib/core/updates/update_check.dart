import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../network/api_client.dart';
import '../storage/storage_providers.dart';
import '../wireguard/native_tunnel_channel.dart';

/// Where releases are published: this project's GitHub releases.
///
/// Overridable at build time so the check can be exercised against another
/// repository's releases. While the repository is private, GitHub answers
/// "not found" and the check finds nothing, which is the intended outcome.
const String releasesRepository = String.fromEnvironment(
  'UPDATE_REPOSITORY',
  defaultValue: 'Parsabrg/vpn',
);

/// A newer release than the one installed.
class AvailableUpdate {
  const AvailableUpdate({required this.version, required this.page});

  /// `0.1.7`, without the tag's `v`.
  final String version;

  /// The release's page, where its notes and APK are.
  final Uri page;
}

/// Compares dotted version numbers: negative, zero or positive, or null for
/// anything that is not one.
///
/// A leading `v` is ignored, and so is anything from `+` or `-` on -- build
/// numbers and pre-release labels are not compared, because a published
/// release is what this is asked about.
int? compareVersions(String a, String b) {
  List<int>? parse(String value) {
    String core = value.trim();
    if (core.startsWith('v') || core.startsWith('V')) {
      core = core.substring(1);
    }
    core = core.split(RegExp(r'[+-]')).first;
    if (core.isEmpty) {
      return null;
    }
    final List<int> parts = <int>[];
    for (final String part in core.split('.')) {
      final int? number = int.tryParse(part);
      if (number == null || number < 0) {
        return null;
      }
      parts.add(number);
    }
    return parts;
  }

  final List<int>? left = parse(a);
  final List<int>? right = parse(b);
  if (left == null || right == null) {
    return null;
  }
  for (int i = 0; i < left.length || i < right.length; i++) {
    final int x = i < left.length ? left[i] : 0;
    final int y = i < right.length ? right[i] : 0;
    if (x != y) {
      return x.compareTo(y);
    }
  }
  return 0;
}

/// The update a release describes, if it is newer than [installed].
///
/// Only a finished release on GitHub itself: drafts and pre-releases are not
/// offered, and a page anywhere but github.com over https is not opened.
AvailableUpdate? updateFromRelease(
  Map<String, dynamic> release,
  String installed,
) {
  if (release['draft'] == true || release['prerelease'] == true) {
    return null;
  }
  final Object? tag = release['tag_name'];
  final Object? url = release['html_url'];
  if (tag is! String || url is! String) {
    return null;
  }
  final Uri? page = Uri.tryParse(url);
  if (page == null || page.scheme != 'https' || page.host != 'github.com') {
    return null;
  }
  final int? order = compareVersions(tag, installed);
  if (order == null || order <= 0) {
    return null;
  }
  final String version = tag.startsWith('v') ? tag.substring(1) : tag;
  return AvailableUpdate(version: version, page: page);
}

/// The latest published release, as GitHub describes it, or null.
abstract interface class ReleaseSource {
  Future<Map<String, dynamic>?> latest();
}

class GitHubReleaseSource implements ReleaseSource {
  GitHubReleaseSource({Dio? dio})
    : _dio =
          dio ??
          Dio(
            BaseOptions(
              connectTimeout: const Duration(seconds: 10),
              receiveTimeout: const Duration(seconds: 10),
              headers: <String, String>{
                'Accept': 'application/vnd.github+json',
              },
            ),
          );

  /// Its own client, not the API's: nothing about the session goes to GitHub.
  final Dio _dio;

  @override
  Future<Map<String, dynamic>?> latest() async {
    try {
      final Response<Map<String, dynamic>> response = await _dio
          .get<Map<String, dynamic>>(
            'https://api.github.com/repos/$releasesRepository/releases/latest',
          );
      return response.data;
    } on Object {
      // Offline, rate-limited, or the repository is not public yet: no
      // update to offer is the right answer to all of them.
      return null;
    }
  }
}

/// Nebula's own API, for while GitHub has nothing to say: the repository's
/// releases are private until it is finished, and GitHub answers "not found"
/// -- which left a Windows PC on 0.1.20 when 0.1.24 was current. Only
/// signed-in apps get an answer; the page offered is still the release on
/// GitHub, as for a public one.
class NebulaReleaseSource implements ReleaseSource {
  NebulaReleaseSource(this._dio);

  final Dio _dio;

  @override
  Future<Map<String, dynamic>?> latest() async {
    try {
      final Response<dynamic> response = await _dio.get<dynamic>(
        '/v1/client/release',
      );
      final Object? body = response.data;
      final Object? version = body is Map<String, dynamic>
          ? body['version']
          : null;
      if (version is! String || compareVersions(version, '0') == null) {
        return null;
      }
      return <String, dynamic>{
        'tag_name': 'v$version',
        'html_url':
            'https://github.com/$releasesRepository/releases/tag/v$version',
      };
    } on Object {
      // Signed out, offline, or a server without the route: nothing to offer.
      return null;
    }
  }
}

/// The first of [sources] that knows of a release.
class FirstReleaseSource implements ReleaseSource {
  const FirstReleaseSource(this.sources);

  final List<ReleaseSource> sources;

  @override
  Future<Map<String, dynamic>?> latest() async {
    for (final ReleaseSource source in sources) {
      final Map<String, dynamic>? release = await source.latest();
      if (release != null) {
        return release;
      }
    }
    return null;
  }
}

final releaseSourceProvider = Provider<ReleaseSource>(
  (Ref ref) => FirstReleaseSource(<ReleaseSource>[
    GitHubReleaseSource(),
    NebulaReleaseSource(ref.watch(dioProvider)),
  ]),
);

/// The installed version as Android reports it (the pubspec version), or
/// null where it cannot say.
final installedVersionProvider = FutureProvider<String?>((Ref ref) async {
  try {
    return await const NativeTunnelChannel().appVersion();
  } on Object {
    return null;
  }
});

/// Whether to ask GitHub for new releases. On unless turned off: asking
/// tells GitHub this app is in use from this address, so it is a choice.
class UpdateChecksController extends Notifier<bool> {
  static const String _key = 'nebula.check_for_updates';

  @override
  bool build() {
    return ref.watch(sharedPreferencesProvider).getBool(_key) ?? true;
  }

  Future<void> setEnabled({required bool enabled}) async {
    state = enabled;
    final SharedPreferences preferences = ref.read(sharedPreferencesProvider);
    await preferences.setBool(_key, enabled);
  }
}

final updateChecksProvider = NotifierProvider<UpdateChecksController, bool>(
  UpdateChecksController.new,
);

/// A newer release, if the check is on and one exists. Asked once per run.
final availableUpdateProvider = FutureProvider<AvailableUpdate?>((
  Ref ref,
) async {
  if (!ref.watch(updateChecksProvider)) {
    return null;
  }
  final String? installed = await ref.watch(installedVersionProvider.future);
  if (installed == null || compareVersions(installed, '0') == null) {
    return null;
  }
  final Map<String, dynamic>? release = await ref
      .read(releaseSourceProvider)
      .latest();
  return release == null ? null : updateFromRelease(release, installed);
});
