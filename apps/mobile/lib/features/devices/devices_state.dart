import '../../core/servers/server_repository.dart';

enum DevicesLoadStatus { loading, failed, loaded }

/// State for the devices/connect screen. A single class (not a sealed
/// hierarchy) because most fields are meaningful across every load status
/// once a first load has completed -- e.g. an in-flight connect action's
/// error should stay visible even if a background reload starts.
class DevicesState {
  const DevicesState({
    required this.loadStatus,
    this.servers = const <AvailableServer>[],
    this.loadErrorMessage,
    this.selectedServerCode,
    this.selectedProfileCode,
    this.peer,
    this.connectedServerCode,
    this.isSubmitting = false,
    this.actionErrorMessage,
  });

  static const DevicesState initial = DevicesState(
    loadStatus: DevicesLoadStatus.loading,
  );

  final DevicesLoadStatus loadStatus;
  final List<AvailableServer> servers;
  final String? loadErrorMessage;
  final String? selectedServerCode;
  final String? selectedProfileCode;

  /// The active WireGuard peer configuration, once a connect request has
  /// succeeded. Provisioning this peer registers the device with the VPN
  /// server -- it does not by itself establish a live tunnel, which needs
  /// native platform integration this app doesn't have yet.
  final WireGuardPeerResult? peer;

  /// Which server [peer] belongs to -- needed to send the right
  /// `server_code` on revoke, since the picker's current selection may have
  /// moved on since connecting.
  final String? connectedServerCode;

  final bool isSubmitting;
  final String? actionErrorMessage;

  bool get isConnected => peer != null;

  AvailableServer? get selectedServer {
    final String? code = selectedServerCode;
    if (code == null) {
      return null;
    }
    for (final AvailableServer server in servers) {
      if (server.code == code) {
        return server;
      }
    }
    return null;
  }

  DevicesState copyWith({
    DevicesLoadStatus? loadStatus,
    List<AvailableServer>? servers,
    String? Function()? loadErrorMessage,
    String? Function()? selectedServerCode,
    String? Function()? selectedProfileCode,
    WireGuardPeerResult? Function()? peer,
    String? Function()? connectedServerCode,
    bool? isSubmitting,
    String? Function()? actionErrorMessage,
  }) {
    return DevicesState(
      loadStatus: loadStatus ?? this.loadStatus,
      servers: servers ?? this.servers,
      loadErrorMessage: loadErrorMessage != null
          ? loadErrorMessage()
          : this.loadErrorMessage,
      selectedServerCode: selectedServerCode != null
          ? selectedServerCode()
          : this.selectedServerCode,
      selectedProfileCode: selectedProfileCode != null
          ? selectedProfileCode()
          : this.selectedProfileCode,
      peer: peer != null ? peer() : this.peer,
      connectedServerCode: connectedServerCode != null
          ? connectedServerCode()
          : this.connectedServerCode,
      isSubmitting: isSubmitting ?? this.isSubmitting,
      actionErrorMessage: actionErrorMessage != null
          ? actionErrorMessage()
          : this.actionErrorMessage,
    );
  }
}
