import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../storage/protection_preference_store.dart';
import '../storage/storage_providers.dart';

/// Holds the two protection toggles and persists every change.
///
/// State is updated before the write is awaited, so the switch moves under the
/// finger rather than after a disk round trip. A failed write therefore leaves
/// the UI ahead of storage until the next launch -- acceptable for a
/// preference, and the alternative is a toggle that visibly lags.
class ProtectionController extends Notifier<ProtectionPreferences> {
  @override
  ProtectionPreferences build() {
    return ref.watch(protectionPreferenceStoreProvider).read();
  }

  Future<void> setConnectOnLaunch({required bool enabled}) {
    return _write(state.copyWith(connectOnLaunch: enabled));
  }

  Future<void> setNotificationSpeed({required bool enabled}) {
    return _write(state.copyWith(notificationSpeed: enabled));
  }

  Future<void> setReconnectAfterRestart({required bool enabled}) {
    return _write(state.copyWith(reconnectAfterRestart: enabled));
  }

  Future<void> setBypassLocalNetwork({required bool enabled}) {
    return _write(state.copyWith(bypassLocalNetwork: enabled));
  }

  Future<void> setBlockWhenVpnDrops({required bool enabled}) {
    return _write(state.copyWith(blockWhenVpnDrops: enabled));
  }

  Future<void> _write(ProtectionPreferences next) async {
    state = next;
    await ref.read(protectionPreferenceStoreProvider).write(next);
  }
}

final protectionControllerProvider =
    NotifierProvider<ProtectionController, ProtectionPreferences>(
      ProtectionController.new,
    );
