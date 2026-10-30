import 'package:shared_preferences/shared_preferences.dart';

/// Which apps are routed around the tunnel.
///
/// Stored as package names, which is what both tunnel backends take: the
/// VpnService `blockedApps` list for Xray, and `ExcludedApplications` in the
/// WireGuard config. Keeping labels here too would mean a stale label after a
/// rename, and the label is never what is matched on.
///
/// Read back defensively for the same reason the server selection is: an app
/// can be uninstalled between one launch and the next, and a package name
/// that no longer exists must not stop the tunnel coming up.
abstract interface class SplitTunnelStore {
  Set<String> readExcludedPackages();
  Future<void> writeExcludedPackages(Set<String> packageNames);
}

class SharedPreferencesSplitTunnelStore implements SplitTunnelStore {
  SharedPreferencesSplitTunnelStore(this._preferences);

  static const String _key = 'nebula.split_tunnel_excluded_packages';

  final SharedPreferences _preferences;

  @override
  Set<String> readExcludedPackages() {
    return (_preferences.getStringList(_key) ?? const <String>[]).toSet();
  }

  @override
  Future<void> writeExcludedPackages(Set<String> packageNames) {
    // Clearing is a real operation: emptying the list has to be remembered,
    // or the next launch restores exclusions the person has just removed.
    if (packageNames.isEmpty) {
      return _preferences.remove(_key);
    }
    // Sorted so the stored value does not churn on every write purely
    // because a Set iterates in whatever order it feels like.
    final List<String> ordered = packageNames.toList()..sort();
    return _preferences.setStringList(_key, ordered);
  }
}

class InMemorySplitTunnelStore implements SplitTunnelStore {
  Set<String> _packages = <String>{};

  @override
  Set<String> readExcludedPackages() => Set<String>.of(_packages);

  @override
  Future<void> writeExcludedPackages(Set<String> packageNames) async {
    _packages = Set<String>.of(packageNames);
  }
}
