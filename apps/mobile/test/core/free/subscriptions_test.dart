import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_riverpod/misc.dart' show Override;
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/free/free_mode.dart';
import 'package:nebula_mobile/core/free/subscriptions.dart';

const String _a =
    'vless://0b6f4a3e-1c2d-4e5f-8a9b-0c1d2e3f4a5b@a.example.test:443'
    '?type=ws&security=tls&sni=a.example.test&path=%2Fws#Alpha';
const String _b =
    'vless://1b6f4a3e-1c2d-4e5f-8a9b-0c1d2e3f4a5b@b.example.test:443'
    '?type=grpc&security=tls&sni=b.example.test&serviceName=g#Beta';

/// [_a] again, under another name: the same connection.
const String _aRenamed =
    'vless://0b6f4a3e-1c2d-4e5f-8a9b-0c1d2e3f4a5b@a.example.test:443'
    '?type=ws&security=tls&sni=a.example.test&path=%2Fws#Same%20server';

/// A stand-in publisher on loopback.
class _Publisher {
  _Publisher(this._server) {
    _server.listen((HttpRequest request) async {
      requests++;
      lastIfNoneMatch = request.headers.value(HttpHeaders.ifNoneMatchHeader);
      if (lastIfNoneMatch == etag) {
        request.response.statusCode = HttpStatus.notModified;
      } else {
        request.response.statusCode = status;
        request.response.headers.set(HttpHeaders.etagHeader, etag);
        request.response.write(body);
      }
      await request.response.close();
    });
  }

  static Future<_Publisher> start() async =>
      _Publisher(await HttpServer.bind(InternetAddress.loopbackIPv4, 0));

  final HttpServer _server;
  String body = '';
  int status = HttpStatus.ok;
  String etag = '"v1"';
  String? lastIfNoneMatch;
  int requests = 0;

  String get url => 'http://127.0.0.1:${_server.port}/sub.txt';

  Future<void> close() => _server.close(force: true);
}

SubscriptionFetcher _fetcher() =>
    SubscriptionFetcher(requireHttps: false, random: Random(1));

final DateTime now = DateTime.utc(2026, 10, 13, 12);

void main() {
  group('decoding', () {
    test('plain lines', () {
      expect(decodeSubscription('$_a\n\n$_b\n'), <String>[_a, _b]);
    });

    test('Base64, standard or URL-safe, wrapped, unpadded', () {
      final String encoded = base64.encode(utf8.encode('$_a\n$_b'));
      final String urlSafe = encoded
          .replaceAll('+', '-')
          .replaceAll('/', '_')
          .replaceAll('=', '');
      final String wrapped = RegExp(
        '.{1,40}',
      ).allMatches(encoded).map((Match m) => m[0]).join('\n');
      for (final String body in <String>[encoded, urlSafe, wrapped]) {
        expect(decodeSubscription(body), <String>[_a, _b]);
      }
    });

    test('anything else is no links, not an error', () {
      expect(decodeSubscription('<html>not found</html>'), isEmpty);
      expect(decodeSubscription(''), isEmpty);
    });

    test('unusable links are counted by scheme and left out', () {
      final ({List<String> links, Map<String, int> skipped}) sorted = sortLinks(
        <String>[_a, 'vmess://abc', 'ss://def', 'ss://ghi', 'garbage', _a],
      );
      expect(sorted.links, <String>[_a]);
      expect(sorted.skipped, <String, int>{
        'vmess': 1,
        'ss': 2,
        'unreadable': 1,
      });
    });

    test('only https addresses are subscribed to', () {
      expect(isSubscriptionAddress('https://example.test/s.txt'), isTrue);
      expect(isSubscriptionAddress('http://example.test/s.txt'), isFalse);
      expect(isSubscriptionAddress('https://user:pw@example.test/'), isFalse);
      expect(isSubscriptionAddress('vless://x'), isFalse);
    });
  });

  group('fetching', () {
    late _Publisher publisher;
    setUp(() async => publisher = await _Publisher.start());
    tearDown(() => publisher.close());

    test('reads the list and schedules the next fetch hours away', () async {
      publisher.body = base64.encode(utf8.encode('$_a\nvmess://x\n$_b'));

      final Subscription s = await _fetcher().refresh(
        Subscription(url: publisher.url),
        now,
      );

      expect(s.links, <String>[_a, _b]);
      expect(s.skipped, <String, int>{'vmess': 1});
      expect(s.failure, isNull);
      expect(s.etag, '"v1"');
      expect(s.nextAt!.difference(now).inHours, inInclusiveRange(5, 7));
    });

    test(
      'asks only for a change, and keeps the list when there is none',
      () async {
        publisher.body = _a;
        final Subscription first = await _fetcher().refresh(
          Subscription(url: publisher.url),
          now,
        );

        final Subscription second = await _fetcher().refresh(first, now);

        expect(publisher.lastIfNoneMatch, '"v1"');
        expect(second.links, <String>[_a]);
        expect(second.checkedAt, now);
      },
    );

    test('a failure keeps the last good list and backs off', () async {
      publisher.body = _a;
      final Subscription good = await _fetcher().refresh(
        Subscription(url: publisher.url),
        now,
      );
      publisher
        ..etag = '"v2"'
        ..status = HttpStatus.internalServerError;

      final Subscription failed = await _fetcher().refresh(good, now);
      final Subscription failedAgain = await _fetcher().refresh(failed, now);

      expect(failed.links, <String>[_a]);
      expect(failed.failure, SubscriptionError.refused);
      expect(failedAgain.failures, 2);
      expect(
        failedAgain.nextAt!.difference(now),
        greaterThan(failed.nextAt!.difference(now)),
      );
    });

    test('a list with nothing usable does not replace a good one', () async {
      publisher.body = _a;
      final Subscription good = await _fetcher().refresh(
        Subscription(url: publisher.url),
        now,
      );
      publisher
        ..etag = '"v2"'
        ..body = 'vmess://only-this';

      final Subscription empty = await _fetcher().refresh(good, now);

      expect(empty.links, <String>[_a]);
      expect(empty.failure, SubscriptionError.empty);
    });

    test('an answer with no content is empty, not refused', () async {
      publisher.status = HttpStatus.noContent;

      final Subscription s = await _fetcher().refresh(
        Subscription(url: publisher.url),
        now,
      );

      expect(s.failure, SubscriptionError.empty);
    });

    test('a body past the limit is refused', () async {
      publisher.body = 'x' * (maxDownloadBytes + 1);

      final Subscription s = await _fetcher().refresh(
        Subscription(url: publisher.url),
        now,
      );

      expect(s.failure, SubscriptionError.tooLarge);
      expect(s.links, isEmpty);
    });

    test('nothing listening is unreachable', () async {
      final String url = publisher.url;
      await publisher.close();

      final Subscription s = await _fetcher().refresh(
        Subscription(url: url),
        now,
      );

      expect(s.failure, SubscriptionError.unreachable);
    });

    test('a plain http address is never fetched by the real fetcher', () async {
      final Subscription s = await SubscriptionFetcher().refresh(
        Subscription(url: publisher.url),
        now,
      );

      expect(s.failure, SubscriptionError.refused);
      expect(publisher.requests, 0);
    });
  });

  group('redirects', () {
    final Uri start = Uri.parse('https://lists.example/sub.txt');

    test('an https hop is followed, relative ones too', () {
      expect(
        redirectTarget(start, 'https://cdn.example/a.txt', 0, true),
        Uri.parse('https://cdn.example/a.txt'),
      );
      expect(
        redirectTarget(start, '/b.txt', 1, true),
        Uri.parse('https://lists.example/b.txt'),
      );
    });

    test('a hop to plain http is refused', () {
      expect(
        redirectTarget(start, 'http://lists.example/sub.txt', 0, true),
        isNull,
      );
      expect(redirectTarget(start, '//evil.example/x', 0, true), isNotNull);
      expect(
        redirectTarget(
          Uri.parse('http://x.example/'),
          '//evil.example/x',
          0,
          true,
        ),
        isNull,
      );
    });

    test('a fourth hop is refused', () {
      expect(redirectTarget(start, '/c.txt', 3, true), isNull);
    });

    test('the fetcher follows a redirect itself', () async {
      final _Publisher target = await _Publisher.start();
      addTearDown(target.close);
      target.body =
          'vless://00000000-0000-4000-8000-000000000000@a.example:443?security=tls&type=ws&sni=a.example#A';
      final HttpServer hop = await HttpServer.bind(
        InternetAddress.loopbackIPv4,
        0,
      );
      addTearDown(() => hop.close(force: true));
      hop.listen((HttpRequest request) async {
        request.response
          ..statusCode = HttpStatus.found
          ..headers.set(HttpHeaders.locationHeader, target.url);
        await request.response.close();
      });

      final Subscription s = await _fetcher().refresh(
        Subscription(url: 'http://127.0.0.1:${hop.port}/start'),
        now,
      );

      expect(s.failure, isNull);
      expect(s.links, hasLength(1));
      expect(target.requests, 1);
    });
  });

  group('in free mode', () {
    test('the same connection twice is listed once, with both sources', () {
      final List<FreeProfile> profiles = freeProfilesFrom(
        builtIn: const <String>[],
        added: const <String>[],
        subscribed: <Subscription>[
          const Subscription(
            url: 'https://one.example/s',
            links: <String>[_a, _b],
          ),
          const Subscription(
            url: 'https://two.example/s',
            links: <String>[_aRenamed],
          ),
        ],
      );

      expect(profiles, hasLength(2));
      // By address: a name can be changed, the address cannot.
      expect(profiles.first.sources, <String>[
        'https://one.example/s',
        'https://two.example/s',
      ]);
    });

    test('one added by hand stays its own, not a subscription\'s', () {
      final List<FreeProfile> profiles = freeProfilesFrom(
        builtIn: const <String>[],
        added: const <String>[_a],
        subscribed: <Subscription>[
          const Subscription(
            url: 'https://one.example/s',
            links: <String>[_aRenamed],
          ),
        ],
      );

      expect(profiles.single.name, 'Alpha');
      expect(profiles.single.sources, <String>['https://one.example/s']);
    });

    test(
      'a refresh that fails leaves the other subscriptions as they were',
      () async {
        final _Publisher working = await _Publisher.start();
        final _Publisher broken = await _Publisher.start();
        addTearDown(working.close);
        addTearDown(broken.close);
        working.body = _a;
        broken.status = HttpStatus.notFound;
        final InMemorySubscriptionStore store = InMemorySubscriptionStore(
          <Subscription>[
            Subscription(url: working.url),
            Subscription(
              url: broken.url,
              links: const <String>[_b],
              checkedAt: now,
            ),
          ],
        );
        final ProviderContainer container = ProviderContainer(
          overrides: <Override>[
            subscriptionStoreProvider.overrideWithValue(store),
            subscriptionFetcherProvider.overrideWithValue(_fetcher()),
          ],
        );
        addTearDown(container.dispose);
        await container.read(subscriptionsProvider.future);

        await container
            .read(subscriptionsProvider.notifier)
            .refresh(force: true);

        final List<Subscription> after = await store.read();
        expect(after[0].links, <String>[_a]);
        expect(after[1].links, <String>[_b]);
        expect(after[1].failure, SubscriptionError.refused);
      },
    );

    test('removing one while a refresh runs keeps it removed', () async {
      final _Publisher slow = await _Publisher.start();
      addTearDown(slow.close);
      slow.body = _a;
      final InMemorySubscriptionStore store = InMemorySubscriptionStore(
        <Subscription>[Subscription(url: slow.url)],
      );
      final ProviderContainer container = ProviderContainer(
        overrides: <Override>[
          subscriptionStoreProvider.overrideWithValue(store),
          subscriptionFetcherProvider.overrideWithValue(_fetcher()),
        ],
      );
      addTearDown(container.dispose);
      await container.read(subscriptionsProvider.future);

      final Future<void> refreshing = container
          .read(subscriptionsProvider.notifier)
          .refresh(force: true);
      await store.write(const <Subscription>[]);
      await refreshing;

      expect(await store.read(), isEmpty);
    });
  });

  test('a name given to a subscription is stored with it', () {
    final Subscription named = const Subscription(
      url: 'https://raw.example.org/base64.txt',
    ).withLabel('WhiteDNS');
    final Subscription back = Subscription.fromJson(named.toJson());
    expect(back.name, 'WhiteDNS');
    expect(back.label, 'WhiteDNS');
  });
}
