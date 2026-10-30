import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/network/api_config.dart';
import 'package:nebula_mobile/core/pairing/pairing.dart';
import 'package:nebula_mobile/core/pairing/pairing_providers.dart';
import 'package:nebula_mobile/core/pairing/pairing_store.dart';
import 'package:nebula_mobile/core/storage/secure_token_store.dart';
import 'package:nebula_mobile/core/storage/storage_providers.dart';

void main() {
  test('a build that carries an address keeps it as its pairing', () async {
    // So the next build, which carries none, still knows where it belongs.
    final InMemoryPairingStore store = InMemoryPairingStore();
    final ProviderContainer container = ProviderContainer(
      overrides: [pairingStoreProvider.overrideWithValue(store)],
    );
    addTearDown(container.dispose);

    final Pairing? pairing = container.read(pairingProvider);
    await Future<void>.delayed(Duration.zero);

    expect(pairing?.apiUrl, ApiConfig.presetBaseUrl);
    expect((await store.read())?.apiUrl, ApiConfig.presetBaseUrl);
  });

  test('a stored pairing wins and is not rewritten', () async {
    final Pairing paired = Pairing.preset('https://api.example.org:8444');
    final InMemoryPairingStore store = InMemoryPairingStore(paired);
    final ProviderContainer container = ProviderContainer(
      overrides: [
        pairingStoreProvider.overrideWithValue(store),
        storedPairingProvider.overrideWithValue(paired),
      ],
    );
    addTearDown(container.dispose);

    expect(container.read(pairingProvider)?.apiUrl, paired.apiUrl);
    expect((await store.read())?.apiUrl, paired.apiUrl);
  });

  Future<(ProviderContainer, InMemorySecureTokenStore)> pairedWith(
    String apiUrl,
  ) async {
    final InMemorySecureTokenStore tokens = InMemorySecureTokenStore();
    await tokens.writeRefreshToken('v1.refresh-from-the-old-server');
    final Pairing paired = Pairing.preset(apiUrl);
    final ProviderContainer container = ProviderContainer(
      overrides: [
        pairingStoreProvider.overrideWithValue(InMemoryPairingStore(paired)),
        storedPairingProvider.overrideWithValue(paired),
        secureTokenStoreProvider.overrideWithValue(tokens),
      ],
    );
    addTearDown(container.dispose);
    return (container, tokens);
  }

  test('pairing another server drops the old session', () async {
    // Kept, its refresh token went to the new server on the first request.
    final (ProviderContainer container, InMemorySecureTokenStore tokens) =
        await pairedWith('https://api.old.example.org');

    await container
        .read(pairingProvider.notifier)
        .adopt(Pairing.preset('https://api.new.example.org'));

    expect(await tokens.readRefreshToken(), isNull);
  });

  test('pairing the same server again keeps the session', () async {
    final (ProviderContainer container, InMemorySecureTokenStore tokens) =
        await pairedWith('https://api.example.org');

    await container
        .read(pairingProvider.notifier)
        .adopt(Pairing.preset('https://api.example.org'));

    expect(await tokens.readRefreshToken(), 'v1.refresh-from-the-old-server');
  });
}
