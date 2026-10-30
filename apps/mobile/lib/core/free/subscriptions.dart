import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import '../servers/profile_link.dart';

/// Subscriptions somebody added in free mode: an HTTPS address that serves a
/// list of connection links, as v2rayNG and its kind read them. Only ones the
/// person chose -- the app ships none -- and nothing about them is sent
/// anywhere but to the address itself.
///
/// The list is untrusted input. It is read within limits, each link goes
/// through the same strict reader as one pasted by hand, and a fetch that
/// fails or comes back unreadable never replaces the last good copy.

/// What one subscription last gave, and how its fetching is going.
class Subscription {
  const Subscription({
    required this.url,
    this.links = const <String>[],
    this.skipped = const <String, int>{},
    this.fetchedAt,
    this.checkedAt,
    this.etag,
    this.lastModified,
    this.error,
    this.failures = 0,
    this.nextAt,
    this.label,
  });

  factory Subscription.fromJson(Map<String, dynamic> json) {
    DateTime? at(String key) =>
        json[key] == null ? null : DateTime.tryParse(json[key] as String);
    return Subscription(
      url: json['url'] as String,
      links: (json['links'] as List<Object?>? ?? const <Object?>[])
          .whereType<String>()
          .toList(),
      skipped: (json['skipped'] as Map<String, dynamic>? ?? const {}).map(
        (String scheme, dynamic count) =>
            MapEntry<String, int>(scheme, count as int),
      ),
      fetchedAt: at('fetchedAt'),
      checkedAt: at('checkedAt'),
      etag: json['etag'] as String?,
      lastModified: json['lastModified'] as String?,
      error: json['error'] as String?,
      failures: json['failures'] as int? ?? 0,
      nextAt: at('nextAt'),
      label: json['label'] as String?,
    );
  }

  final String url;

  /// The name the person gave it, or null for the host.
  final String? label;

  /// The same, under [label] -- empty for none.
  Subscription withLabel(String? label) {
    final String? trimmed = label?.trim();
    return Subscription(
      url: url,
      links: links,
      skipped: skipped,
      fetchedAt: fetchedAt,
      checkedAt: checkedAt,
      etag: etag,
      lastModified: lastModified,
      error: error,
      failures: failures,
      nextAt: nextAt,
      label: trimmed == null || trimmed.isEmpty ? null : trimmed,
    );
  }

  /// The last good list: links this app can connect with, as published.
  final List<String> links;

  /// Links left out, by scheme (`vmess`, `ss`, ...) or `unreadable`.
  final Map<String, int> skipped;

  /// When [links] last changed from a successful fetch.
  final DateTime? fetchedAt;

  /// When the address last answered, changed or not.
  final DateTime? checkedAt;
  final String? etag;
  final String? lastModified;

  /// The last attempt's failure, or null when it worked.
  SubscriptionError? get failure =>
      error == null ? null : SubscriptionError.values.asNameMap()[error];
  final String? error;

  /// Failures in a row, which space the retries out.
  final int failures;

  /// Not fetched again on its own before this.
  final DateTime? nextAt;

  /// The host, which is what a person recognises it by.
  String get name => label ?? Uri.tryParse(url)?.host ?? url;

  bool due(DateTime now) => nextAt == null || !now.isBefore(nextAt!);

  Map<String, dynamic> toJson() => <String, dynamic>{
    'url': url,
    'links': links,
    'skipped': skipped,
    if (fetchedAt != null) 'fetchedAt': fetchedAt!.toIso8601String(),
    if (checkedAt != null) 'checkedAt': checkedAt!.toIso8601String(),
    'etag': ?etag,
    'lastModified': ?lastModified,
    'error': ?error,
    'failures': failures,
    if (nextAt != null) 'nextAt': nextAt!.toIso8601String(),
    'label': ?label,
  };
}

enum SubscriptionError {
  /// Could not connect, or no answer in time.
  unreachable,

  /// Answered with an error status.
  refused,

  /// More than [maxDownloadBytes], or more than [maxDecodedBytes] decoded.
  tooLarge,

  /// Answered, but held no link this app can use.
  empty,
}

/// Lists in use run from a few kilobytes to a few hundred; past this it is
/// not a list a person can mean to use.
const int maxDownloadBytes = 2 * 1024 * 1024;
const int maxDecodedBytes = 4 * 1024 * 1024;

/// Usable links kept per subscription. A list longer than this is cut, not
/// refused: the rest of it still works.
const int maxLinksKept = 300;

/// A few times a day: the lists change about that often, and their hosts
/// (GitHub's raw files, mostly) ask that they are not polled harder.
/// Where a redirect from [at] to [location] leads, or null when it must not
/// be followed: after three hops, or anywhere but https when [requireHttps].
@visibleForTesting
Uri? redirectTarget(Uri at, String location, int hop, bool requireHttps) {
  final Uri next = at.resolve(location);
  if (hop >= 3 || (requireHttps && next.scheme != 'https')) {
    return null;
  }
  return next;
}

const Duration refreshInterval = Duration(hours: 6);
const Duration _maxBackoff = Duration(hours: 12);

/// Whether [text] is an address this app will fetch from: HTTPS only.
bool isSubscriptionAddress(String text) {
  final Uri? uri = Uri.tryParse(text.trim());
  return uri != null &&
      uri.scheme == 'https' &&
      uri.host.isNotEmpty &&
      uri.userInfo.isEmpty;
}

/// The links in a subscription body: plain lines, or the whole body (or
/// each line) in Base64 -- standard or URL-safe, padded or not, wrapped or
/// not. Anything else reads as no links.
List<String> decodeSubscription(String body) {
  final String text = body.trim();
  if (text.isEmpty) {
    return const <String>[];
  }
  if (text.contains('://')) {
    return <String>[
      for (final String line in const LineSplitter().convert(text))
        if (line.trim().isNotEmpty)
          line.trim().contains('://')
              ? line.trim()
              : (_base64(line.trim()) ?? line.trim()),
    ];
  }
  final String? decoded = _base64(text);
  if (decoded == null || !decoded.contains('://')) {
    return const <String>[];
  }
  return decodeSubscription(decoded);
}

String? _base64(String text) {
  String compact = text.replaceAll(RegExp(r'\s'), '');
  compact = compact.replaceAll('-', '+').replaceAll('_', '/');
  compact = compact.padRight((compact.length + 3) ~/ 4 * 4, '=');
  try {
    return utf8.decode(base64.decode(compact), allowMalformed: true);
  } on FormatException {
    return null;
  }
}

/// The usable links in [lines] -- distinct, at most [maxLinksKept] -- and a
/// count of the rest by scheme.
({List<String> links, Map<String, int> skipped}) sortLinks(List<String> lines) {
  final List<String> links = <String>[];
  final Set<String> seen = <String>{};
  final Map<String, int> skipped = <String, int>{};
  for (final String line in lines) {
    if (parseLink(line) != null) {
      if (links.length < maxLinksKept && seen.add(line)) {
        links.add(line);
      }
      continue;
    }
    final int at = line.indexOf('://');
    final String scheme = at > 0 && at < 16
        ? line.substring(0, at).toLowerCase()
        : 'unreadable';
    skipped[scheme] = (skipped[scheme] ?? 0) + 1;
  }
  return (links: links, skipped: skipped);
}

/// Fetches one subscription. [requireHttps] is off only in tests, whose
/// stand-in server is plain HTTP on loopback.
class SubscriptionFetcher {
  SubscriptionFetcher({
    this.timeout = const Duration(seconds: 15),
    this.requireHttps = true,
    Random? random,
  }) : _random = random ?? Random();

  final Duration timeout;
  final bool requireHttps;
  final Random _random;

  /// [current] refreshed: new links when the list changed, the same ones
  /// when it did not or could not be read, and the next time to try.
  Future<Subscription> refresh(Subscription current, DateTime now) async {
    final Uri uri = Uri.parse(current.url);
    if (requireHttps && uri.scheme != 'https') {
      return _failed(current, SubscriptionError.refused, now);
    }
    final HttpClient client = HttpClient()..connectionTimeout = timeout;
    try {
      // Redirects followed here rather than by the client, which would
      // follow one to plain http: the list would then arrive unencrypted,
      // and anyone on the path could hand over servers of their choosing.
      Uri at = uri;
      HttpClientResponse response;
      for (int hop = 0; ; hop++) {
        final HttpClientRequest request = await client
            .getUrl(at)
            .timeout(timeout);
        request.followRedirects = false;
        if (current.links.isNotEmpty) {
          if (current.etag != null) {
            request.headers.set(HttpHeaders.ifNoneMatchHeader, current.etag!);
          }
          if (current.lastModified != null) {
            request.headers.set(
              HttpHeaders.ifModifiedSinceHeader,
              current.lastModified!,
            );
          }
        }
        response = await request.close().timeout(timeout);
        final String? location = response.headers.value(
          HttpHeaders.locationHeader,
        );
        if (!response.isRedirect || location == null) {
          break;
        }
        await response.drain<void>();
        final Uri? next = redirectTarget(at, location, hop, requireHttps);
        if (next == null) {
          return _failed(current, SubscriptionError.refused, now);
        }
        at = next;
      }
      if (response.statusCode == HttpStatus.notModified) {
        await response.drain<void>();
        return _succeeded(current, now);
      }
      if (response.statusCode == HttpStatus.noContent) {
        // It answered, with nothing in it: empty, not refused.
        await response.drain<void>();
        return _failed(current, SubscriptionError.empty, now);
      }
      if (response.statusCode != HttpStatus.ok) {
        await response.drain<void>();
        return _failed(current, SubscriptionError.refused, now);
      }
      final List<int>? bytes = await _read(response);
      if (bytes == null) {
        return _failed(current, SubscriptionError.tooLarge, now);
      }
      final String body = utf8.decode(bytes, allowMalformed: true);
      final List<String> lines = decodeSubscription(body);
      if (lines.fold<int>(0, (int sum, String l) => sum + l.length) >
          maxDecodedBytes) {
        return _failed(current, SubscriptionError.tooLarge, now);
      }
      final ({List<String> links, Map<String, int> skipped}) sorted = sortLinks(
        lines,
      );
      if (sorted.links.isEmpty) {
        // Kept apart from a fetch that failed: the address works, it just
        // has nothing this app can use -- and the last good list stays.
        return _failed(
          current,
          SubscriptionError.empty,
          now,
          skipped: sorted.skipped,
        );
      }
      return _succeeded(
        Subscription(
          url: current.url,
          label: current.label,
          links: sorted.links,
          skipped: sorted.skipped,
          fetchedAt: now,
          etag: response.headers.value(HttpHeaders.etagHeader),
          lastModified: response.headers.value(HttpHeaders.lastModifiedHeader),
        ),
        now,
      );
    } on Object {
      return _failed(current, SubscriptionError.unreachable, now);
    } finally {
      client.close(force: true);
    }
  }

  Future<List<int>?> _read(HttpClientResponse response) async {
    if (response.contentLength > maxDownloadBytes) {
      return null;
    }
    final BytesBuilder bytes = BytesBuilder(copy: false);
    await for (final List<int> chunk in response.timeout(timeout)) {
      bytes.add(chunk);
      if (bytes.length > maxDownloadBytes) {
        return null;
      }
    }
    return bytes.takeBytes();
  }

  /// A spread of up to a tenth either side, so many devices that added the
  /// same list do not all ask for it at once.
  Duration _jittered(Duration base) {
    final int spread = base.inSeconds ~/ 10;
    return base + Duration(seconds: _random.nextInt(2 * spread + 1) - spread);
  }

  Subscription _succeeded(Subscription s, DateTime now) => Subscription(
    url: s.url,
    label: s.label,
    links: s.links,
    skipped: s.skipped,
    fetchedAt: s.fetchedAt ?? now,
    checkedAt: now,
    etag: s.etag,
    lastModified: s.lastModified,
    nextAt: now.add(_jittered(refreshInterval)),
  );

  Subscription _failed(
    Subscription s,
    SubscriptionError error,
    DateTime now, {
    Map<String, int>? skipped,
  }) {
    final int failures = s.failures + 1;
    // 15 min, 30, 60, ... up to 12 h.
    final Duration wait = Duration(
      minutes: min(15 * pow(2, failures - 1).toInt(), _maxBackoff.inMinutes),
    );
    return Subscription(
      url: s.url,
      label: s.label,
      links: s.links,
      skipped: skipped ?? s.skipped,
      fetchedAt: s.fetchedAt,
      checkedAt: s.checkedAt,
      etag: s.etag,
      lastModified: s.lastModified,
      error: error.name,
      failures: failures,
      nextAt: now.add(_jittered(wait)),
    );
  }
}

/// The subscriptions and their last good lists. Secure storage: a list's
/// links carry the credentials that admit to their servers.
abstract interface class SubscriptionStore {
  Future<List<Subscription>> read();
  Future<void> write(List<Subscription> subscriptions);
}

/// Bumped by every write of the links or the subscriptions, so a reader
/// that keeps them can tell it must read again.
int linksVersion = 0;

class FlutterSecureSubscriptionStore implements SubscriptionStore {
  FlutterSecureSubscriptionStore({FlutterSecureStorage? storage})
    : _storage = storage ?? const FlutterSecureStorage();

  static const String _key = 'nebula.free_subscriptions';

  final FlutterSecureStorage _storage;

  @override
  Future<List<Subscription>> read() async {
    try {
      final String? stored = await _storage.read(key: _key);
      return stored == null
          ? const <Subscription>[]
          : (jsonDecode(stored) as List<Object?>)
                .whereType<Map<String, dynamic>>()
                .map(Subscription.fromJson)
                .toList();
    } on Object {
      return const <Subscription>[];
    }
  }

  /// One write of the whole list, so a refresh interrupted part way leaves
  /// the previous list rather than half of a new one.
  @override
  Future<void> write(List<Subscription> subscriptions) async {
    await _storage.write(
      key: _key,
      value: jsonEncode(<Map<String, dynamic>>[
        for (final Subscription s in subscriptions) s.toJson(),
      ]),
    );
    // After: a read between the two would keep the old list.
    linksVersion++;
  }
}

class InMemorySubscriptionStore implements SubscriptionStore {
  InMemorySubscriptionStore([List<Subscription> start = const []])
    : _subscriptions = <Subscription>[...start];

  List<Subscription> _subscriptions;

  @override
  Future<List<Subscription>> read() async => <Subscription>[..._subscriptions];

  @override
  Future<void> write(List<Subscription> subscriptions) async {
    linksVersion++;
    _subscriptions = <Subscription>[...subscriptions];
  }
}
