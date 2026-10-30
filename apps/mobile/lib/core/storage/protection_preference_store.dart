import 'package:shared_preferences/shared_preferences.dart';

/// The protection settings, as one value.
///
/// Together rather than as two independent flags because the settings screen
/// reads and writes them as a pair, and a single immutable value means a
/// widget cannot observe one of them mid-write and render a half-applied
/// state.
class ProtectionPreferences {
  const ProtectionPreferences({
    required this.connectOnLaunch,
    required this.notificationSpeed,
    required this.bypassLocalNetwork,
    this.reconnectAfterRestart = true,
    this.blockWhenVpnDrops = false,
  });

  /// Reconnect to the last used server when the app starts.
  final bool connectOnLaunch;

  /// Show the live download and upload speed in the tunnel's notification.
  ///
  /// Not whether there is a notification at all: Android requires one for
  /// as long as a VPN runs, so a switch that claimed to hide it could never
  /// have worked -- and the one that sat here did nothing. The stored key is
  /// the old one, so a person who turned that off keeps a quiet notification.
  final bool notificationSpeed;

  /// Leave the local network reachable while the tunnel is up -- a printer, a
  /// NAS, a router's admin page.
  ///
  /// Off by default, and deliberately. On means the tunnel does not claim the
  /// private ranges, and anything that can be reached at one of those
  /// addresses is then reached directly. That is almost always a machine in
  /// the same room, but "almost always" is not the default this app should
  /// pick for somebody whose threat model is their network operator.
  final bool bypassLocalNetwork;

  /// Bring a tunnel that was up back after the phone restarts or the app is
  /// updated. Read by the Android side as well as here (RestartReceiver), so
  /// the stored key is part of that contract.
  ///
  /// On by default: it only ever restores a connection somebody left on.
  final bool reconnectAfterRestart;

  /// Windows and Linux: while connected, nothing leaves except through the
  /// tunnel, to the VPN server or on the local network -- and if the tunnel
  /// dies, that holds until it reconnects or the person disconnects. Android
  /// has the system's own (Always-on VPN), which the app links to instead.
  ///
  /// Off by default: with it on, a VPN that cannot connect means no internet
  /// at all, Iranian sites included, and that has to be a choice.
  final bool blockWhenVpnDrops;

  /// Both on. The design draws both toggles on, and both are the safer
  /// default: a VPN that reconnects itself and says so in the shade is
  /// harder to be wrong about than one that quietly does neither.
  static const ProtectionPreferences defaults = ProtectionPreferences(
    connectOnLaunch: true,
    notificationSpeed: true,
    bypassLocalNetwork: false,
  );

  ProtectionPreferences copyWith({
    bool? connectOnLaunch,
    bool? notificationSpeed,
    bool? bypassLocalNetwork,
    bool? reconnectAfterRestart,
    bool? blockWhenVpnDrops,
  }) {
    return ProtectionPreferences(
      connectOnLaunch: connectOnLaunch ?? this.connectOnLaunch,
      notificationSpeed: notificationSpeed ?? this.notificationSpeed,
      bypassLocalNetwork: bypassLocalNetwork ?? this.bypassLocalNetwork,
      reconnectAfterRestart:
          reconnectAfterRestart ?? this.reconnectAfterRestart,
      blockWhenVpnDrops: blockWhenVpnDrops ?? this.blockWhenVpnDrops,
    );
  }

  @override
  bool operator ==(Object other) {
    return other is ProtectionPreferences &&
        other.connectOnLaunch == connectOnLaunch &&
        other.notificationSpeed == notificationSpeed &&
        other.bypassLocalNetwork == bypassLocalNetwork &&
        other.reconnectAfterRestart == reconnectAfterRestart &&
        other.blockWhenVpnDrops == blockWhenVpnDrops;
  }

  @override
  int get hashCode => Object.hash(
    connectOnLaunch,
    notificationSpeed,
    bypassLocalNetwork,
    reconnectAfterRestart,
    blockWhenVpnDrops,
  );
}

abstract interface class ProtectionPreferenceStore {
  ProtectionPreferences read();
  Future<void> write(ProtectionPreferences preferences);
}

class SharedPreferencesProtectionStore implements ProtectionPreferenceStore {
  SharedPreferencesProtectionStore(this._preferences);

  static const String _connectKey = 'nebula.connect_on_launch';
  // Named for the switch this replaced; kept so its setting carries over.
  static const String _notificationKey = 'nebula.tunnel_notification';
  static const String _bypassLocalKey = 'nebula.bypass_local_network';
  // Also read natively by RestartReceiver as `flutter.` + this key.
  static const String _reconnectKey = 'nebula.reconnect_after_restart';
  static const String _blockWhenVpnDropsKey = 'nebula.block_when_vpn_drops';

  final SharedPreferences _preferences;

  @override
  ProtectionPreferences read() {
    // A missing key means never set, which must read as the default rather
    // than as false -- `getBool` returning null is not the user turning
    // something off.
    return ProtectionPreferences(
      connectOnLaunch:
          _preferences.getBool(_connectKey) ??
          ProtectionPreferences.defaults.connectOnLaunch,
      notificationSpeed:
          _preferences.getBool(_notificationKey) ??
          ProtectionPreferences.defaults.notificationSpeed,
      bypassLocalNetwork:
          _preferences.getBool(_bypassLocalKey) ??
          ProtectionPreferences.defaults.bypassLocalNetwork,
      reconnectAfterRestart:
          _preferences.getBool(_reconnectKey) ??
          ProtectionPreferences.defaults.reconnectAfterRestart,
      blockWhenVpnDrops: _preferences.getBool(_blockWhenVpnDropsKey) ?? false,
    );
  }

  @override
  Future<void> write(ProtectionPreferences preferences) async {
    await _preferences.setBool(_connectKey, preferences.connectOnLaunch);
    await _preferences.setBool(_notificationKey, preferences.notificationSpeed);
    await _preferences.setBool(_bypassLocalKey, preferences.bypassLocalNetwork);
    await _preferences.setBool(
      _reconnectKey,
      preferences.reconnectAfterRestart,
    );
    await _preferences.setBool(
      _blockWhenVpnDropsKey,
      preferences.blockWhenVpnDrops,
    );
  }
}

/// In-memory fake for tests.
class InMemoryProtectionStore implements ProtectionPreferenceStore {
  ProtectionPreferences _preferences = ProtectionPreferences.defaults;

  @override
  ProtectionPreferences read() => _preferences;

  @override
  Future<void> write(ProtectionPreferences preferences) async {
    _preferences = preferences;
  }
}
