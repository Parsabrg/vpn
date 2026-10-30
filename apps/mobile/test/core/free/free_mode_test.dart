import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_riverpod/misc.dart' show Override;
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/free/free_mode.dart';
import 'package:nebula_mobile/core/servers/server_repository.dart';
import 'package:nebula_mobile/core/settings/advanced_settings_controller.dart';
import 'package:nebula_mobile/core/storage/storage_providers.dart';
import 'package:shared_preferences/shared_preferences.dart';

const String _builtIn =
    'vless://0f1e2d3c-4b5a-4978-8a6b-5c4d3e2f1a0b@188.114.97.6:443'
    '?security=tls&type=ws&sni=relay.example.workers.dev&path=%2F#Nebula%20relay';
const String _mine =
    'vless://11111111-1111-4111-8111-111111111111@104.16.1.1:8443'
    '?security=tls&type=ws&sni=mine.example.workers.dev&path=%2Fws#Mine';

Future<ProviderContainer> _container({
  List<String> builtIn = const <String>[_builtIn],
  InMemoryFreeLinkStore? store,
  Map<String, Object> stored = const <String, Object>{},
}) async {
  SharedPreferences.setMockInitialValues(stored);
  final SharedPreferences preferences = await SharedPreferences.getInstance();
  return ProviderContainer(
    overrides: <Override>[
      sharedPreferencesProvider.overrideWithValue(preferences),
      builtInFreeLinksProvider.overrideWithValue(builtIn),
      freeLinkStoreProvider.overrideWithValue(store ?? InMemoryFreeLinkStore()),
    ],
  );
}

void main() {
  group('the list', () {
    test('the build comes first, and each link once', () {
      final List<FreeProfile> profiles = freeProfilesFrom(
        builtIn: <String>[_builtIn],
        added: <String>[_mine, _builtIn, 'vless://nonsense', '  $_mine '],
      );
      expect(profiles.map((FreeProfile p) => p.name), <String>[
        'Nebula relay',
        'Mine',
      ]);
      expect(profiles.first.builtIn, isTrue);
      expect(profiles.last.builtIn, isFalse);
      expect(profiles.last.client.sni, 'mine.example.workers.dev');
    });

    test('a link keeps its code from one run to the next', () {
      String codeOf(String link) => freeProfilesFrom(
        builtIn: const <String>[],
        added: <String>[link],
      ).single.code;
      expect(codeOf(_mine), codeOf(' $_mine\n'));
      expect(codeOf(_mine), isNot(codeOf(_builtIn)));
      expect(codeOf(_mine), matches(RegExp(r'^free-[0-9a-f]{8}$')));
    });
  });

  group('instead of a server', () {
    late LocalServerRepository repository;
    setUp(() {
      repository = LocalServerRepository(
        builtIn: const <String>[_builtIn],
        store: InMemoryFreeLinkStore(<String>[_mine]),
      );
    });

    test('each link is a server with the one profile it describes', () async {
      final List<AvailableServer> servers = await repository
          .listAvailableServers();
      expect(servers.map((AvailableServer s) => s.displayName), <String>[
        'Nebula relay',
        'Mine',
      ]);
      final AvailableProfile profile = servers.last.profiles.single;
      expect(profile.code, 'vless-websocket-tls');
      expect(profile.protocolCode, 'vless');
      expect(profile.requiredPort, 8443);
    });

    test(
      'the credential is the link, and nothing is issued or revoked',
      () async {
        final List<AvailableServer> servers = await repository
            .listAvailableServers();
        final XrayClientResult client = await repository.requestXrayClient(
          deviceId: freeDeviceId,
          serverCode: servers.last.code,
          protocolProfileCode: 'vless-websocket-tls',
        );
        expect(client.uuid, '11111111-1111-4111-8111-111111111111');
        expect(client.serverAddress, '104.16.1.1');
        await repository.revokeXrayClient(
          deviceId: freeDeviceId,
          serverCode: servers.last.code,
          protocolProfileCode: 'vless-websocket-tls',
        );
        expect(
          () => repository.requestXrayClient(
            deviceId: freeDeviceId,
            serverCode: 'free-00000000',
            protocolProfileCode: 'vless-websocket-tls',
          ),
          throwsStateError,
        );
      },
    );
  });

  group('entering and leaving', () {
    test('entering is remembered, and gives the screens a device', () async {
      final ProviderContainer container = await _container();
      addTearDown(container.dispose);
      expect(container.read(freeModeProvider), isFalse);

      await container.read(freeModeProvider.notifier).enter();

      expect(container.read(freeModeProvider), isTrue);
      expect(
        container.read(sharedPreferencesProvider).getBool(freeModeKey),
        isTrue,
      );
      expect(container.read(deviceIdStoreProvider).read(), freeDeviceId);
      // A shared relay's requests are counted: what does not need it stays
      // off it.
      expect(
        container.read(advancedSettingsControllerProvider).iranDirect,
        isTrue,
      );
      // The list and the credentials are now this device's own.
      expect(
        container.read(serverRepositoryProvider),
        isA<LocalServerRepository>(),
      );

      await container.read(freeModeProvider.notifier).leave();

      expect(container.read(freeModeProvider), isFalse);
      expect(container.read(deviceIdStoreProvider).read(), isNull);
    });

    test('a device id from a sign-in is left alone', () async {
      final ProviderContainer container = await _container(
        stored: <String, Object>{'nebula.device_id': 'device-from-server'},
      );
      addTearDown(container.dispose);
      await container.read(freeModeProvider.notifier).enter();
      await container.read(freeModeProvider.notifier).leave();
      expect(
        container.read(deviceIdStoreProvider).read(),
        'device-from-server',
      );
    });
  });

  group('adding a relay', () {
    test('a link is kept; one that cannot be used is refused', () async {
      final InMemoryFreeLinkStore store = InMemoryFreeLinkStore();
      final ProviderContainer container = await _container(store: store);
      addTearDown(container.dispose);
      await container.read(freeProfilesProvider.future);
      final FreeProfilesNotifier notifier = container.read(
        freeProfilesProvider.notifier,
      );

      expect(
        await notifier.add('trojan://x@example.com:443?allowInsecure=1'),
        isFalse,
      );
      expect(await notifier.add(' $_mine '), isTrue);
      // Taken, and left as it was.
      expect(await notifier.add(_mine), isTrue);

      expect(await store.read(), <String>[_mine]);
      expect(
        container
            .read(freeProfilesProvider)
            .value!
            .map((FreeProfile p) => p.name),
        <String>['Nebula relay', 'Mine'],
      );

      await notifier.remove(_mine);
      expect(await store.read(), isEmpty);
      expect(container.read(freeProfilesProvider).value, hasLength(1));
    });
  });
}
