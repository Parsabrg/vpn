import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../network/api_config.dart';
import '../storage/storage_providers.dart';
import 'pairing.dart';
import 'pairing_store.dart';

final pairingStoreProvider = Provider<PairingStore>((Ref ref) {
  return FlutterSecurePairingStore();
});

/// What was stored when the app started, read in `main()` before the first
/// frame so the first request already goes to the right place. Overridden
/// there; `null` means nothing was stored.
final storedPairingProvider = Provider<Pairing?>((Ref ref) => null);

final pairingClientProvider = Provider<PairingClient>((Ref ref) {
  return PairingClient();
});

/// The deployment this app talks to, or `null` when it must be paired first.
///
/// A stored pairing wins; otherwise a build that carries an address
/// (`--dart-define=API_BASE_URL`, or the development default) uses that, as
/// every build did before pairing existed.
final pairingProvider = NotifierProvider<PairingNotifier, Pairing?>(
  PairingNotifier.new,
);

class PairingNotifier extends Notifier<Pairing?> {
  @override
  Pairing? build() {
    final Pairing? stored = ref.read(storedPairingProvider);
    if (stored != null) {
      return stored;
    }
    final String? preset = ApiConfig.presetBaseUrl;
    if (preset == null) {
      return null;
    }
    // Kept as if paired, so a later build that carries no address -- every
    // public release, once the repository is public -- still knows where it
    // belongs instead of asking every existing user to pair again. A failed
    // write costs only that: the next generic build asks once.
    final Pairing pairing = Pairing.preset(preset);
    unawaited(
      ref.read(pairingStoreProvider).write(pairing).catchError((Object _) {}),
    );
    return pairing;
  }

  Future<void> adopt(Pairing pairing) async {
    final Pairing? previous = state;
    if (previous == null ||
        previous.apiUrl != pairing.apiUrl ||
        previous.deploymentId != pairing.deploymentId) {
      // A session belongs to the deployment that issued it. Kept, the
      // previous one's refresh token went to the new server on the first
      // request (2026-10-29): a credential handed to someone else's server,
      // and a "your session ended" on a server never signed in to.
      await ref.read(secureTokenStoreProvider).clear();
    }
    await ref.read(pairingStoreProvider).write(pairing);
    state = pairing;
  }

  /// Back to the pairing screen: the person asked to change server, so the
  /// build's own address is not quietly put back in its place. (It applies
  /// again at the next launch if nothing new is paired.) The caller signs
  /// out first: a session belongs to the deployment that issued it.
  Future<void> forget() async {
    await ref.read(pairingStoreProvider).clear();
    state = null;
  }
}
