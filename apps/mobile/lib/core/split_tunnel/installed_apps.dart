/// The apps on this device, for choosing which ones bypass the tunnel.
///
/// Reads through the same platform channel the WireGuard tunnel uses rather
/// than a package off pub.dev: the list has to agree with what the VpnService
/// will actually accept, and both ends of that are already in MainActivity.
library;

import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_riverpod/misc.dart' show FutureProviderFamily;

class InstalledApp {
  const InstalledApp({
    required this.packageName,
    required this.label,
    required this.isSystem,
  });

  final String packageName;
  final String label;

  /// Shipped with the phone. Reported rather than filtered on -- a
  /// pre-installed browser or maps app is exactly the kind of thing somebody
  /// wants outside the tunnel, so hiding system apps would remove the most
  /// useful entries from the list.
  final bool isSystem;
}

abstract interface class InstalledAppCatalogue {
  Future<List<InstalledApp>> list();

  /// PNG bytes, or null when the app went away between listing and drawing.
  Future<Uint8List?> icon(String packageName);
}

class PlatformInstalledAppCatalogue implements InstalledAppCatalogue {
  const PlatformInstalledAppCatalogue([
    this._channel = const MethodChannel('org.nebulavpn/wireguard_tunnel'),
  ]);

  final MethodChannel _channel;

  @override
  Future<List<InstalledApp>> list() async {
    final List<Object?>? raw = await _channel.invokeMethod<List<Object?>>(
      'installedApps',
    );
    if (raw == null) {
      return const <InstalledApp>[];
    }
    return raw.whereType<Map<Object?, Object?>>().map((
      Map<Object?, Object?> entry,
    ) {
      return InstalledApp(
        packageName: entry['packageName']! as String,
        label: entry['label']! as String,
        isSystem: (entry['isSystem'] as bool?) ?? false,
      );
    }).toList();
  }

  @override
  Future<Uint8List?> icon(String packageName) {
    return _channel.invokeMethod<Uint8List>('appIcon', <String, Object?>{
      'packageName': packageName,
    });
  }
}

/// Empty on anything that is not Android. Split tunnelling is a VpnService
/// feature; a desktop build asking for this should get an empty list rather
/// than a MissingPluginException.
class NoInstalledApps implements InstalledAppCatalogue {
  const NoInstalledApps();

  @override
  Future<List<InstalledApp>> list() async => const <InstalledApp>[];

  @override
  Future<Uint8List?> icon(String packageName) async => null;
}

final Provider<InstalledAppCatalogue> installedAppCatalogueProvider =
    Provider<InstalledAppCatalogue>((Ref ref) {
      return const PlatformInstalledAppCatalogue();
    });

/// The list, fetched once and held. Enumerating every package and reading its
/// label is a few hundred binder calls, which is not something to repeat each
/// time the picker rebuilds.
final FutureProvider<List<InstalledApp>> installedAppsProvider =
    FutureProvider<List<InstalledApp>>((Ref ref) {
      return ref.watch(installedAppCatalogueProvider).list();
    });

final FutureProviderFamily<Uint8List?, String> appIconProvider =
    FutureProvider.family<Uint8List?, String>((Ref ref, String packageName) {
      return ref.watch(installedAppCatalogueProvider).icon(packageName);
    });
