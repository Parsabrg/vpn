import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/free/free_mode.dart';
import 'package:nebula_mobile/core/free/subscriptions.dart';
import 'package:nebula_mobile/core/servers/server_repository.dart';

import '../../features/devices/fake_server_repository.dart';

const String _mine =
    'vless://11111111-1111-4111-8111-111111111111@104.16.1.1:8443'
    '?security=tls&type=ws&sni=mine.example.workers.dev&path=%2Fws#Mine';

const String _relay =
    'vless://0f1e2d3c-4b5a-4978-8a6b-5c4d3e2f1a0b@188.114.97.6:443'
    '?security=tls&type=ws&sni=relay.example.workers.dev&path=%2F#Nebula%20relay';
const String _fromSub1 =
    'vless://22222222-2222-4222-8222-222222222222@104.16.2.2:2053'
    '?security=tls&type=ws&sni=relay.example.org&path=%2Fa#WS-CF-auto';
const String _fromSub2 =
    'vless://22222222-2222-4222-8222-222222222222@104.16.2.2:8443'
    '?security=tls&type=xhttp&sni=relay.example.org&path=%2Fb#xHTTP-CF-auto';

const AvailableServer _server = AvailableServer(
  code: 'study-lab-1',
  displayName: 'Example VPS',
  publicHost: 'api.example.test',
  profiles: <AvailableProfile>[
    AvailableProfile(
      code: 'vless-ws-tls',
      displayName: 'VLESS WS',
      protocolId: 'p',
      protocolCode: 'vless',
      adBlock: false,
    ),
  ],
);

void main() {
  test('signed in, the server comes first and your links after it', () async {
    final FakeServerRepository server = FakeServerRepository()
      ..servers = <AvailableServer>[_server];
    final InMemoryFreeLinkStore store = InMemoryFreeLinkStore();
    await store.write(<String>[_mine]);
    final CombinedServerRepository combined = CombinedServerRepository(
      server: server,
      own: LocalServerRepository(
        builtIn: const <String>[],
        store: store,
        subscriptions: InMemorySubscriptionStore(<Subscription>[
          const Subscription(
            url: 'https://relay.example.org/sub',
            links: <String>[_fromSub1, _fromSub2],
          ),
        ]),
        importedName: () => 'Imported',
      ),
    );

    final List<AvailableServer> listed = await combined.listAvailableServers();
    // Three entries, not one per link: the server, the links added by
    // hand, and the subscription with its links as the choices.
    expect(listed, hasLength(3));
    expect(listed[0].displayName, 'Example VPS');
    expect(listed[1].displayName, 'Imported');
    expect(
      listed[1].profiles.map((AvailableProfile p) => p.displayName),
      <String>['Mine'],
    );
    expect(
      listed[2].profiles.map((AvailableProfile p) => p.displayName),
      <String>['WS-CF-auto', 'xHTTP-CF-auto'],
    );
    final XrayClientResult fromSub = await combined.requestXrayClient(
      deviceId: 'd',
      serverCode: listed[2].code,
      protocolProfileCode: listed[2].profiles.last.code,
    );
    expect(fromSub.transport, 'xhttp');

    // A link is this device's to hand out and to take back: the server is
    // never asked about it, and has nothing to revoke.
    final AvailableServer link = listed[1];
    expect(isOwnLinkCode(link.code), isTrue);
    expect(isOwnLinkCode(_server.code), isFalse);
    final XrayClientResult client = await combined.requestXrayClient(
      deviceId: 'd',
      serverCode: link.code,
      protocolProfileCode: link.profiles.single.code,
    );
    expect(client.serverAddress, '104.16.1.1');
    await combined.revokeXrayClient(
      deviceId: 'd',
      serverCode: link.code,
      protocolProfileCode: link.profiles.single.code,
    );
    expect(server.requestXrayClientCalls, 0);
    expect(server.revokeXrayClientCalls, 0);

    server.requestXrayClientResult = client;
    await combined.requestXrayClient(
      deviceId: 'd',
      serverCode: _server.code,
      protocolProfileCode: 'vless-ws-tls',
    );
    expect(server.requestXrayClientCalls, 1);
  });

  test(
    'free mode groups too: the shared relays, yours, a subscription',
    () async {
      final InMemoryFreeLinkStore store = InMemoryFreeLinkStore();
      await store.write(<String>[_mine]);
      final LocalServerRepository free = LocalServerRepository(
        builtIn: const <String>[_relay],
        store: store,
        subscriptions: InMemorySubscriptionStore(<Subscription>[
          const Subscription(
            url: 'https://relay.example.org/sub',
            links: <String>[_fromSub1, _fromSub2],
          ),
        ]),
        importedName: () => 'Imported',
        builtInName: () => 'Shared relays',
      );

      final List<AvailableServer> listed = await free.listAvailableServers();

      expect(listed.map((AvailableServer s) => s.displayName).take(2), <String>[
        'Shared relays',
        'Imported',
      ]);
      expect(listed, hasLength(3));
      expect(listed[2].profiles, hasLength(2));
      final XrayClientResult relay = await free.requestXrayClient(
        deviceId: 'd',
        serverCode: listed[0].code,
        protocolProfileCode: listed[0].profiles.single.code,
      );
      expect(relay.sni, 'relay.example.workers.dev');
    },
  );

  test('a named subscription keeps its place when renamed', () async {
    // The entry is found by its address: renaming it does not lose the
    // choice made in it, or its links' record.
    final InMemorySubscriptionStore subscriptions = InMemorySubscriptionStore(
      <Subscription>[
        const Subscription(
          url: 'https://raw.example.org/base64.txt',
          links: <String>[_fromSub1],
        ),
      ],
    );
    LocalServerRepository repository() => LocalServerRepository(
      builtIn: const <String>[],
      store: InMemoryFreeLinkStore(),
      subscriptions: subscriptions,
      importedName: () => 'Imported',
    );
    final AvailableServer before =
        (await repository().listAvailableServers()).single;
    expect(before.displayName, 'raw.example.org');

    await subscriptions.write(<Subscription>[
      for (final Subscription s in await subscriptions.read())
        s.withLabel('  WhiteDNS  '),
    ]);
    final AvailableServer after =
        (await repository().listAvailableServers()).single;

    expect(after.displayName, 'WhiteDNS');
    expect(after.code, before.code);
    expect(
      (await subscriptions.read()).single.withLabel('').name,
      'raw.example.org',
    );
  });
}
