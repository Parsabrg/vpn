import 'package:flutter_riverpod/flutter_riverpod.dart';

/// Whether the last network call reached the API at all. Deliberately not
/// backed by a `connectivity_plus`-style OS radio check -- the app already
/// makes an HTTP call on every screen that matters, so inferring offline
/// from an actual failed request (`NebulaConnectivityException`) is enough
/// signal without an extra dependency, and avoids a false "online" reading
/// from a radio that's up but can't actually reach the server.
enum ConnectivityState { online, offline }

class ConnectivityNotifier extends Notifier<ConnectivityState> {
  @override
  ConnectivityState build() => ConnectivityState.online;

  void markOffline() {
    state = ConnectivityState.offline;
  }

  void markOnline() {
    state = ConnectivityState.online;
  }
}

final connectivityProvider =
    NotifierProvider<ConnectivityNotifier, ConnectivityState>(
      ConnectivityNotifier.new,
    );
