import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/network/error_copy.dart';
import '../../core/network/network_guard.dart';
import '../../core/servers/server_repository.dart';
import '../../core/storage/storage_providers.dart';
import '../../core/storage/wireguard_key_store.dart';
import '../../core/wireguard/wireguard_keys.dart';
import 'devices_state.dart';

class DevicesController extends Notifier<DevicesState> {
  late final ServerRepository _repository;
  late final WireGuardKeyStore _keyStore;
  static const WireGuardKeyGenerator _keyGenerator = WireGuardKeyGenerator();

  @override
  DevicesState build() {
    _repository = ref.watch(serverRepositoryProvider);
    _keyStore = ref.watch(wireGuardKeyStoreProvider);
    return DevicesState.initial;
  }

  Future<void> load() async {
    state = state.copyWith(loadStatus: DevicesLoadStatus.loading);
    try {
      final List<AvailableServer> servers = await runGuarded(
        ref,
        _repository.listAvailableServers,
      );
      state = state.copyWith(
        loadStatus: DevicesLoadStatus.loaded,
        servers: servers,
      );
    } catch (error) {
      state = state.copyWith(
        loadStatus: DevicesLoadStatus.failed,
        loadErrorMessage: () => userFacingErrorMessage(error),
      );
    }
  }

  void selectServer(String serverCode) {
    state = state.copyWith(
      selectedServerCode: () => serverCode,
      // Changing servers invalidates any profile chosen for the old one.
      selectedProfileCode: () => null,
    );
  }

  void selectProfile(String profileCode) {
    state = state.copyWith(selectedProfileCode: () => profileCode);
  }

  Future<void> connect(String deviceId) async {
    final String? serverCode = state.selectedServerCode;
    final String? profileCode = state.selectedProfileCode;
    if (serverCode == null || profileCode == null) {
      return;
    }

    state = state.copyWith(isSubmitting: true, actionErrorMessage: () => null);
    try {
      final WireGuardKeyPair keyPair = await _currentOrNewKeyPair();
      final WireGuardPeerResult result = await runGuarded(
        ref,
        () => _repository.requestPeer(
          deviceId: deviceId,
          serverCode: serverCode,
          publicKey: keyPair.publicKeyBase64,
        ),
      );
      state = state.copyWith(
        isSubmitting: false,
        peer: () => result,
        connectedServerCode: () => serverCode,
      );
    } catch (error) {
      state = state.copyWith(
        isSubmitting: false,
        actionErrorMessage: () => userFacingErrorMessage(error),
      );
    }
  }

  Future<void> disconnect(String deviceId) async {
    final String? serverCode = state.connectedServerCode;
    if (serverCode == null) {
      return;
    }

    state = state.copyWith(isSubmitting: true, actionErrorMessage: () => null);
    try {
      await runGuarded(
        ref,
        () =>
            _repository.revokePeer(deviceId: deviceId, serverCode: serverCode),
      );
      state = state.copyWith(
        isSubmitting: false,
        peer: () => null,
        connectedServerCode: () => null,
      );
    } catch (error) {
      state = state.copyWith(
        isSubmitting: false,
        actionErrorMessage: () => userFacingErrorMessage(error),
      );
    }
  }

  /// Reuses this install's existing WireGuard identity if one was already
  /// generated, rather than minting a new key pair (and therefore a new
  /// peer identity) on every connect attempt.
  Future<WireGuardKeyPair> _currentOrNewKeyPair() async {
    final String? storedPrivateKey = await _keyStore.readPrivateKey();
    if (storedPrivateKey != null) {
      return _keyGenerator.fromStoredPrivateKey(storedPrivateKey);
    }
    final WireGuardKeyPair generated = await _keyGenerator.generate();
    await _keyStore.writePrivateKey(generated.privateKeyBase64);
    return generated;
  }
}

final devicesControllerProvider =
    NotifierProvider<DevicesController, DevicesState>(DevicesController.new);
