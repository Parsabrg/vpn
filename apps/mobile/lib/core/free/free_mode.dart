import 'dart:convert';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import '../servers/profile_link.dart';
import '../servers/server_repository.dart';
import '../settings/advanced_settings_controller.dart';
import '../storage/device_id_store.dart';
import '../storage/storage_providers.dart';
import 'subscriptions.dart';

/// Using the app with no Nebula server: connections come from `vless://`
/// links -- the build's own relay, and any the person adds -- and stay on
/// this device. There is no account, and no server is told anything.

/// The relays this build comes with, as links separated by whitespace
/// (`--dart-define=FREE_LINKS=...`). A deployment's value, like the API
/// address: never in source.
const String _builtInLinks = String.fromEnvironment('FREE_LINKS');

/// What the controller is given where a signed-in device has its id. Nothing
/// answers to it.
const String freeDeviceId = 'free';

typedef FreeProfile = ({
  String code,
  String name,
  String link,
  bool builtIn,
  XrayClientResult client,

  /// The subscriptions it came from, by address -- not by name, which the
  /// person can change; empty for one of the build's or one added by hand.
  List<String> sources,
});

/// The links somebody added. Secure storage: each carries the UUID that
/// admits to its relay.
abstract interface class FreeLinkStore {
  Future<List<String>> read();
  Future<void> write(List<String> links);
}

class FlutterSecureFreeLinkStore implements FreeLinkStore {
  FlutterSecureFreeLinkStore({FlutterSecureStorage? storage})
    : _storage = storage ?? const FlutterSecureStorage();

  static const String _key = 'nebula.free_links';

  final FlutterSecureStorage _storage;

  @override
  Future<List<String>> read() async {
    try {
      final String? stored = await _storage.read(key: _key);
      return stored == null
          ? const <String>[]
          : (jsonDecode(stored) as List<Object?>).whereType<String>().toList();
    } on Object {
      return const <String>[];
    }
  }

  @override
  Future<void> write(List<String> links) async {
    await _storage.write(key: _key, value: jsonEncode(links));
    linksVersion++;
  }
}

class InMemoryFreeLinkStore implements FreeLinkStore {
  InMemoryFreeLinkStore([List<String> links = const <String>[]])
    : _links = <String>[...links];

  List<String> _links;

  @override
  Future<List<String>> read() async => <String>[..._links];

  @override
  Future<void> write(List<String> links) async {
    linksVersion++;
    _links = <String>[...links];
  }
}

final freeLinkStoreProvider = Provider<FreeLinkStore>(
  (Ref ref) => FlutterSecureFreeLinkStore(),
);

/// The build's own links. A provider so a test can name some.
final builtInFreeLinksProvider = Provider<List<String>>(
  (Ref ref) => _builtInLinks
      .split(RegExp(r'\s+'))
      .where((String link) => link.isNotEmpty)
      .toList(),
);

/// Whether [serverCode] is one of this device's own links rather than a
/// server's: those have no account behind them to ask about access.
bool isOwnLinkCode(String? serverCode) =>
    serverCode != null && serverCode.startsWith('free-');

/// A code that stays the same for the same link, so the choice made last
/// time and the credential saved for it are found again.
String _codeFor(String link) {
  int hash = 0x811c9dc5;
  for (final int unit in link.codeUnits) {
    hash = ((hash ^ unit) * 0x01000193) & 0xffffffff;
  }
  return 'free-${hash.toRadixString(16).padLeft(8, '0')}';
}

/// What actually decides where a link connects, so the same server published
/// under two names, or in two subscriptions, is listed once.
String _connectionKey(XrayClientResult c) => <Object?>[
  c.protocol,
  c.uuid,
  c.password,
  c.method,
  c.flow,
  c.transportSecurity,
  c.realityPublicKey,
  c.realityShortId,
  c.serverAddress.toLowerCase(),
  c.port,
  c.sni.toLowerCase(),
  c.transport,
  c.path,
  c.serviceName,
].join('|');

/// Every usable profile: the build's first, then the person's own, then
/// their subscriptions'. A link that no longer reads is left out rather than
/// offered and failed, and one already listed under another name only adds
/// its subscription to the first one's sources.
List<FreeProfile> freeProfilesFrom({
  required List<String> builtIn,
  required List<String> added,
  List<Subscription> subscribed = const <Subscription>[],
}) {
  final Map<String, int> byKey = <String, int>{};
  final List<FreeProfile> profiles = <FreeProfile>[];
  void take(String raw, {required bool own, String? source}) {
    final String link = raw.trim();
    final ImportedProfile? profile = parseLink(link);
    if (profile == null) {
      return;
    }
    final String key = _connectionKey(profile.client);
    final int? at = byKey[key];
    if (at != null) {
      final FreeProfile first = profiles[at];
      if (source != null && !first.sources.contains(source)) {
        profiles[at] = (
          code: first.code,
          name: first.name,
          link: first.link,
          builtIn: first.builtIn,
          client: first.client,
          sources: <String>[...first.sources, source],
        );
      }
      return;
    }
    byKey[key] = profiles.length;
    profiles.add((
      code: _codeFor(key),
      name: profile.name,
      link: link,
      builtIn: own,
      client: profile.client,
      sources: <String>[?source],
    ));
  }

  for (final String link in builtIn) {
    take(link, own: true);
  }
  for (final String link in added) {
    take(link, own: false);
  }
  for (final Subscription subscription in subscribed) {
    for (final String link in subscription.links) {
      take(link, own: false, source: subscription.url);
    }
  }
  return profiles;
}

/// What was stored when the app started, read in `main()` beside the
/// pairing. Overridden there; nothing stored reads as a server being used.
final storedFreeModeProvider = Provider<bool>((Ref ref) => false);

const String freeModeKey = 'nebula.free_mode';

/// Whether the app is being used without a server.
final freeModeProvider = NotifierProvider<FreeModeNotifier, bool>(
  FreeModeNotifier.new,
);

class FreeModeNotifier extends Notifier<bool> {
  @override
  bool build() => ref.read(storedFreeModeProvider);

  Future<void> enter() async {
    await ref.read(sharedPreferencesProvider).setBool(freeModeKey, true);
    // The screens hand the controller this device's id; with no server there
    // is none, and one left by an earlier sign-in is as good as any.
    final DeviceIdStore deviceId = ref.read(deviceIdStoreProvider);
    if (deviceId.read() == null) {
      await deviceId.write(freeDeviceId);
    }
    // A relay's requests are counted and shared: what does not need it stays
    // off it. The switch is in Settings like any other.
    await ref
        .read(advancedSettingsControllerProvider.notifier)
        .setIranDirect(enabled: true);
    state = true;
  }

  /// Back to the door. The caller disconnects first.
  Future<void> leave() async {
    await ref.read(sharedPreferencesProvider).setBool(freeModeKey, false);
    final DeviceIdStore deviceId = ref.read(deviceIdStoreProvider);
    if (deviceId.read() == freeDeviceId) {
      await deviceId.clear();
    }
    state = false;
  }
}

/// The list the free screen shows and edits.
final freeProfilesProvider =
    AsyncNotifierProvider<FreeProfilesNotifier, List<FreeProfile>>(
      FreeProfilesNotifier.new,
    );

class FreeProfilesNotifier extends AsyncNotifier<List<FreeProfile>> {
  @override
  Future<List<FreeProfile>> build() async => freeProfilesFrom(
    builtIn: ref.watch(builtInFreeLinksProvider),
    added: await ref.watch(freeLinkStoreProvider).read(),
    subscribed: await ref.watch(subscriptionsProvider.future),
  );

  /// False for a link this app cannot connect with, so the field can say so.
  /// One already listed is taken and left as it was.
  Future<bool> add(String link) async {
    final String text = link.trim();
    if (parseLink(text) == null) {
      return false;
    }
    final FreeLinkStore store = ref.read(freeLinkStoreProvider);
    final List<String> links = await store.read();
    if (!links.contains(text)) {
      await store.write(<String>[...links, text]);
      ref.invalidateSelf();
      await future;
    }
    return true;
  }

  /// Removes a link added by hand. One from a subscription comes back with
  /// its next refresh; the subscription is what is removed instead.
  Future<void> remove(String link) async {
    final FreeLinkStore store = ref.read(freeLinkStoreProvider);
    await store.write(<String>[
      for (final String kept in await store.read())
        if (kept != link) kept,
    ]);
    ref.invalidateSelf();
    await future;
  }
}

/// The server list and the credentials, from this device instead of a
/// server: each link is a "server" with the one profile it describes.
class LocalServerRepository implements ServerRepository {
  LocalServerRepository({
    required this.builtIn,
    required this.store,
    SubscriptionStore? subscriptions,
    this.importedName,
    this.builtInName,
  }) : subscriptions = subscriptions ?? InMemorySubscriptionStore();

  final List<String> builtIn;
  final FreeLinkStore store;
  final SubscriptionStore subscriptions;

  /// When set, the links are listed as groups -- the build's relays (named
  /// [builtInName]), the links added by hand (named this), and one per
  /// subscription -- each with its links as its choices, rather than a
  /// server per link: a subscription of 122 links buried everything else.
  /// Null only where a test wants a server per link.
  final String Function()? importedName;
  final String Function()? builtInName;

  /// The code of the group holding the build's relays.
  static const String builtInCode = 'free-builtin';

  /// The code of the group holding the links added by hand.
  static const String importedCode = 'free-imported';

  /// The code of a subscription's group.
  /// From its address, so renaming it keeps the choice made in it and the
  /// record of its links.
  static String subscriptionCode(String url) =>
      'free-sub-${_codeFor(url).substring(5)}';

  /// Read once until a link or a subscription is written: testing a group
  /// of a hundred links read secure storage and parsed every list once per
  /// link, and took minutes.
  Future<List<FreeProfile>> _profiles() {
    if (_read == null || _readVersion != linksVersion) {
      _readVersion = linksVersion;
      _read = _load();
    }
    return _read!;
  }

  Future<List<FreeProfile>> _load() async {
    final List<Subscription> subscribed = await subscriptions.read();
    _names = <String, String>{
      for (final Subscription s in subscribed) s.url: s.name,
    };
    return freeProfilesFrom(
      builtIn: builtIn,
      added: await store.read(),
      subscribed: subscribed,
    );
  }

  /// Each subscription's name now, by address.
  Map<String, String> _names = const <String, String>{};

  Future<List<FreeProfile>>? _read;
  int? _readVersion;

  static String profileCodeOf(XrayClientResult client) =>
      client.transport == 'hysteria'
      ? 'hysteria2'
      : '${client.protocol}-${client.transport}-${client.transportSecurity}';

  static String displayNameOf(XrayClientResult client) {
    if (client.transport == 'hysteria') {
      return 'Hysteria2';
    }
    final String protocol = switch (client.protocol) {
      'trojan' => 'Trojan',
      'shadowsocks' => 'Shadowsocks',
      _ => 'VLESS',
    };
    if (client.protocol == 'shadowsocks') {
      return protocol;
    }
    final String transport = switch (client.transport) {
      'websocket' => 'WebSocket',
      'grpc' => 'gRPC',
      'xhttp' => 'XHTTP',
      _ => client.transportSecurity == 'reality' ? 'REALITY' : 'TCP',
    };
    return '$protocol $transport';
  }

  @override
  Future<List<AvailableServer>> listAvailableServers() async {
    final List<FreeProfile> profiles = await _profiles();
    if (importedName == null) {
      return _onePerLink(profiles);
    }
    final String imported = importedName!();
    AvailableProfile choice(FreeProfile profile) => AvailableProfile(
      // The link's own code: it is what picks the link out of its group.
      code: profile.code,
      displayName: profile.name,
      protocolId: profile.code,
      protocolCode: profile.client.transport == 'hysteria'
          ? 'hysteria2'
          : profile.client.protocol,
      adBlock: false,
      requiredPort: profile.client.port,
    );
    final List<FreeProfile> shipped = <FreeProfile>[
      for (final FreeProfile p in profiles)
        if (p.builtIn) p,
    ];
    final List<FreeProfile> byHand = <FreeProfile>[
      for (final FreeProfile p in profiles)
        if (p.sources.isEmpty && !p.builtIn) p,
    ];
    final Map<String, List<FreeProfile>> bySubscription =
        <String, List<FreeProfile>>{};
    for (final FreeProfile p in profiles) {
      if (p.sources.isNotEmpty) {
        (bySubscription[p.sources.first] ??= <FreeProfile>[]).add(p);
      }
    }
    return <AvailableServer>[
      if (shipped.isNotEmpty)
        AvailableServer(
          code: builtInCode,
          displayName: builtInName?.call() ?? imported,
          publicHost: '',
          profiles: <AvailableProfile>[
            for (final FreeProfile p in shipped) choice(p),
          ],
        ),
      if (byHand.isNotEmpty)
        AvailableServer(
          code: importedCode,
          displayName: imported,
          publicHost: '',
          profiles: <AvailableProfile>[
            for (final FreeProfile p in byHand) choice(p),
          ],
        ),
      for (final MapEntry<String, List<FreeProfile>> group
          in bySubscription.entries)
        AvailableServer(
          code: subscriptionCode(group.key),
          displayName:
              _names[group.key] ?? Uri.tryParse(group.key)?.host ?? group.key,
          publicHost: '',
          profiles: <AvailableProfile>[
            for (final FreeProfile p in group.value) choice(p),
          ],
        ),
    ];
  }

  List<AvailableServer> _onePerLink(List<FreeProfile> profiles) =>
      <AvailableServer>[
        for (final FreeProfile profile in profiles)
          AvailableServer(
            code: profile.code,
            displayName: profile.name,
            publicHost: profile.client.serverAddress,
            profiles: <AvailableProfile>[
              AvailableProfile(
                code: profileCodeOf(profile.client),
                displayName: displayNameOf(profile.client),
                protocolId: profile.code,
                protocolCode: profile.client.transport == 'hysteria'
                    ? 'hysteria2'
                    : profile.client.protocol,
                adBlock: false,
                requiredPort: profile.client.port,
              ),
            ],
          ),
      ];

  @override
  Future<XrayClientResult> requestXrayClient({
    required String deviceId,
    required String serverCode,
    required String protocolProfileCode,
  }) async {
    // Grouped, the choice names the link; one per link, the server does.
    final String wanted = importedName == null
        ? serverCode
        : protocolProfileCode;
    for (final FreeProfile profile in await _profiles()) {
      if (profile.code == wanted) {
        return profile.client;
      }
    }
    throw StateError('This connection is no longer in the list.');
  }

  /// Nothing was issued, so there is nothing to take back.
  @override
  Future<void> revokeXrayClient({
    required String deviceId,
    required String serverCode,
    required String protocolProfileCode,
  }) async {}

  @override
  Future<WireGuardPeerResult> requestPeer({
    required String deviceId,
    required String serverCode,
    required String protocolProfileCode,
    required String publicKey,
  }) => throw UnsupportedError('A link has no WireGuard profile.');

  @override
  Future<void> revokePeer({
    required String deviceId,
    required String serverCode,
  }) async {}
}

/// A server's list with this device's own links after it: someone signed in
/// to a server can keep other links and subscriptions too -- a setup of
/// their own as a backup, say. Each link is handled here, everything
/// else by the server.
class CombinedServerRepository implements ServerRepository {
  CombinedServerRepository({required this.server, required this.own});

  final ServerRepository server;
  final LocalServerRepository own;

  ServerRepository _for(String serverCode) =>
      isOwnLinkCode(serverCode) ? own : server;

  @override
  Future<List<AvailableServer>> listAvailableServers() async =>
      <AvailableServer>[
        ...await server.listAvailableServers(),
        ...await own.listAvailableServers(),
      ];

  @override
  Future<XrayClientResult> requestXrayClient({
    required String deviceId,
    required String serverCode,
    required String protocolProfileCode,
  }) => _for(serverCode).requestXrayClient(
    deviceId: deviceId,
    serverCode: serverCode,
    protocolProfileCode: protocolProfileCode,
  );

  @override
  Future<void> revokeXrayClient({
    required String deviceId,
    required String serverCode,
    required String protocolProfileCode,
  }) => _for(serverCode).revokeXrayClient(
    deviceId: deviceId,
    serverCode: serverCode,
    protocolProfileCode: protocolProfileCode,
  );

  @override
  Future<WireGuardPeerResult> requestPeer({
    required String deviceId,
    required String serverCode,
    required String protocolProfileCode,
    required String publicKey,
  }) => _for(serverCode).requestPeer(
    deviceId: deviceId,
    serverCode: serverCode,
    protocolProfileCode: protocolProfileCode,
    publicKey: publicKey,
  );

  @override
  Future<void> revokePeer({
    required String deviceId,
    required String serverCode,
  }) => _for(serverCode).revokePeer(deviceId: deviceId, serverCode: serverCode);
}

final subscriptionStoreProvider = Provider<SubscriptionStore>(
  (Ref ref) => FlutterSecureSubscriptionStore(),
);

final subscriptionFetcherProvider = Provider<SubscriptionFetcher>(
  (Ref ref) => SubscriptionFetcher(),
);

/// The subscriptions the free screen shows and edits.
final subscriptionsProvider =
    AsyncNotifierProvider<SubscriptionsNotifier, List<Subscription>>(
      SubscriptionsNotifier.new,
    );

class SubscriptionsNotifier extends AsyncNotifier<List<Subscription>> {
  /// One refresh at a time: a second tap waits for the first.
  Future<void>? _running;

  @override
  Future<List<Subscription>> build() =>
      ref.watch(subscriptionStoreProvider).read();

  /// Adds and fetches it. False for an address that is not HTTPS; one
  /// already added is left as it was.
  Future<bool> add(String address) async {
    final String url = address.trim();
    if (!isSubscriptionAddress(url)) {
      return false;
    }
    final SubscriptionStore store = ref.read(subscriptionStoreProvider);
    final List<Subscription> current = await store.read();
    if (current.every((Subscription s) => s.url != url)) {
      await store.write(<Subscription>[...current, Subscription(url: url)]);
    }
    await refresh(only: url);
    return true;
  }

  Future<void> remove(String url) async {
    final SubscriptionStore store = ref.read(subscriptionStoreProvider);
    await store.write(<Subscription>[
      for (final Subscription s in await store.read())
        if (s.url != url) s,
    ]);
    ref.invalidateSelf();
    await future;
  }

  /// Names a subscription; an empty [label] goes back to its host.
  Future<void> rename(String url, String label) async {
    final SubscriptionStore store = ref.read(subscriptionStoreProvider);
    await store.write(<Subscription>[
      for (final Subscription s in await store.read())
        s.url == url ? s.withLabel(label) : s,
    ]);
    ref.invalidateSelf();
    await future;
  }

  /// Fetches what is due -- or everything when [force]d, or just [only] --
  /// one subscription after another, and stores the result in one write.
  /// Only the list changes: a tunnel that is up stays up.
  Future<void> refresh({bool force = false, String? only}) async {
    final Future<void>? running = _running;
    if (running != null) {
      await running;
    }
    final Future<void> run = _refresh(force: force, only: only);
    _running = run;
    try {
      await run;
    } finally {
      if (identical(_running, run)) {
        _running = null;
      }
    }
  }

  Future<void> _refresh({required bool force, String? only}) async {
    final SubscriptionStore store = ref.read(subscriptionStoreProvider);
    final SubscriptionFetcher fetcher = ref.read(subscriptionFetcherProvider);
    final List<Subscription> current = await store.read();
    final DateTime now = DateTime.now().toUtc();
    final Map<String, Subscription> fetched = <String, Subscription>{};
    for (final Subscription s in current) {
      final bool wanted = only == null ? (force || s.due(now)) : s.url == only;
      if (wanted) {
        fetched[s.url] = await fetcher.refresh(s, now);
      }
    }
    if (fetched.isEmpty) {
      return;
    }
    // Re-read before writing: one removed while this was fetching stays
    // removed, and one added meanwhile stays added.
    await store.write(<Subscription>[
      for (final Subscription s in await store.read()) fetched[s.url] ?? s,
    ]);
    ref.invalidateSelf();
    await future;
  }
}
