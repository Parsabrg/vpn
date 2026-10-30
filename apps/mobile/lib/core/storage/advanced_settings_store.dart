import 'dart:io';

import 'package:shared_preferences/shared_preferences.dart';

/// The core-level knobs other clients expose, as one value.
///
/// Every default here reproduces exactly what the app did before any of these
/// existed. That is the rule this file is built around: adding a setting must
/// not change the behaviour of an installation whose owner never opens the
/// screen. A working tunnel that quietly starts behaving differently after an
/// update is worse than a missing feature, and on these networks the person
/// has no way to tell which change broke it.
///
/// Each one is also a real lever on the generated config rather than a
/// remembered preference -- a switch that stores a value nothing reads is
/// worse than no switch, because it makes a promise.
class AdvancedSettings {
  const AdvancedSettings({
    required this.dnsServers,
    required this.muxEnabled,
    required this.muxConcurrency,
    required this.sniffing,
    required this.logLevel,
    required this.fragment,
    this.routingMode = RoutingMode.everything,
    this.connectionMode = ConnectionMode.vpn,
    this.localProxyPort = defaultLocalProxyPort,
    this.bypassDomains = const <String>[],
    this.iranDirect = false,
    this.cleanIp,
    this.cleanIpHost,
  });

  /// Resolvers the tunnel declares. Empty means "whatever the profile
  /// chooses", which is the shipped behaviour: AdGuard's filtering resolver
  /// for an ad-block profile and its non-filtering one otherwise.
  ///
  /// Never left genuinely unset. Declaring no resolver does not mean "no
  /// DNS" -- it hands DNS to the underlying network, which on the networks
  /// this app exists for both observes and forges it, sending a client to a
  /// blockpage address before any tunnelled connection is attempted.
  final List<String> dnsServers;

  /// Multiplex several streams over one connection.
  ///
  /// Off by default and worth leaving off unless something is actually
  /// wrong: it reduces handshakes on a lossy link, and it also makes the
  /// traffic pattern more distinctive, which is the opposite of what is
  /// wanted where connections are classified rather than merely counted.
  final bool muxEnabled;
  final int muxConcurrency;

  /// Read the hostname out of each connection.
  ///
  /// tun2socks hands the core packets addressed by IP, so without this there
  /// is no name for any routing rule to match on. Needed by ad-blocking, and
  /// by anything else that routes on domains; it costs a parse per
  /// connection and exposes the name to the core's own routing.
  final SniffingMode sniffing;

  final XrayLogLevel logLevel;

  /// Split the outgoing TLS handshake across several small writes.
  ///
  /// The one setting here aimed squarely at the networks this app exists
  /// for. Inspection that blocks by server name has to read that name out of
  /// the TLS client hello, and a hello delivered in pieces is one a
  /// middlebox has to reassemble before it can match -- which many do not.
  ///
  /// Off by default, because it is not free: it adds a write per fragment
  /// and is itself a distinctive pattern. It is the thing to reach for when a
  /// server answers a plain TCP probe but the connection dies during the
  /// handshake, which is what name-based blocking looks like from here.
  final FragmentSettings fragment;

  /// Which traffic goes through the server at all.
  ///
  /// Kept here because the tunnel config is rendered from these settings,
  /// but deliberately not counted by [isDefault] and not undone by the
  /// Advanced screen's reset: it is switched from Settings, as a choice
  /// about what the app is for, not as a tuning knob.
  final RoutingMode routingMode;

  /// A VPN for the whole phone, or a local SOCKS5 proxy for the apps that
  /// are pointed at it. Like [routingMode], a choice made in Settings and
  /// kept by the Advanced screen's reset.
  final ConnectionMode connectionMode;

  /// The port the local proxy listens on in [ConnectionMode.localProxy],
  /// chosen by the person using it, because the apps pointed at it are set
  /// up with it by hand. Not the VPN mode's port, which is picked fresh for
  /// every connection and never needs to be known.
  final int localProxyPort;

  /// Websites that connect directly instead of through the server, each
  /// with its subdomains -- for a local bank or service that refuses
  /// foreign addresses. Xray profiles only: WireGuard and Hysteria2 have no
  /// domain routing. Like [routingMode], a choice made in Settings and kept
  /// by the Advanced screen's reset.
  final List<String> bypassDomains;

  /// Iranian addresses and websites (`.ir` and Xray's `category-ir` list)
  /// connect directly, over the person's own connection, instead of through
  /// the server. Xray profiles only, and a Settings choice like
  /// [bypassDomains].
  final bool iranDirect;

  /// The Cloudflare address the CDN route is dialled at, chosen by a scan
  /// (see core/cdn/clean_ip.dart), and the route name it was chosen for.
  /// Used only while that is still the route's name: a scan for one
  /// deployment's route says nothing about another. Null means whatever
  /// DNS gives, as before.
  final String? cleanIp;
  final String? cleanIpHost;

  /// Not 10808 or 10809: those are v2rayNG's, and two proxies cannot share
  /// a port.
  static const int defaultLocalProxyPort = 10820;

  static const AdvancedSettings defaults = AdvancedSettings(
    dnsServers: <String>[],
    muxEnabled: false,
    muxConcurrency: 8,
    sniffing: SniffingMode.whenRoutingNeedsIt,
    logLevel: XrayLogLevel.warning,
    fragment: FragmentSettings.defaults,
  );

  AdvancedSettings copyWith({
    List<String>? dnsServers,
    bool? muxEnabled,
    int? muxConcurrency,
    SniffingMode? sniffing,
    XrayLogLevel? logLevel,
    FragmentSettings? fragment,
    RoutingMode? routingMode,
    ConnectionMode? connectionMode,
    int? localProxyPort,
    List<String>? bypassDomains,
    bool? iranDirect,
    String? Function()? cleanIp,
    String? Function()? cleanIpHost,
  }) {
    return AdvancedSettings(
      dnsServers: dnsServers ?? this.dnsServers,
      muxEnabled: muxEnabled ?? this.muxEnabled,
      muxConcurrency: muxConcurrency ?? this.muxConcurrency,
      sniffing: sniffing ?? this.sniffing,
      logLevel: logLevel ?? this.logLevel,
      fragment: fragment ?? this.fragment,
      routingMode: routingMode ?? this.routingMode,
      connectionMode: connectionMode ?? this.connectionMode,
      localProxyPort: localProxyPort ?? this.localProxyPort,
      bypassDomains: bypassDomains ?? this.bypassDomains,
      iranDirect: iranDirect ?? this.iranDirect,
      cleanIp: cleanIp == null ? this.cleanIp : cleanIp(),
      cleanIpHost: cleanIpHost == null ? this.cleanIpHost : cleanIpHost(),
    );
  }

  bool get isDefault =>
      dnsServers.isEmpty &&
      muxEnabled == defaults.muxEnabled &&
      muxConcurrency == defaults.muxConcurrency &&
      sniffing == defaults.sniffing &&
      logLevel == defaults.logLevel &&
      fragment == defaults.fragment;

  @override
  bool operator ==(Object other) {
    return other is AdvancedSettings &&
        _sameList(other.dnsServers, dnsServers) &&
        other.muxEnabled == muxEnabled &&
        other.muxConcurrency == muxConcurrency &&
        other.sniffing == sniffing &&
        other.logLevel == logLevel &&
        other.fragment == fragment &&
        other.routingMode == routingMode &&
        other.connectionMode == connectionMode &&
        other.localProxyPort == localProxyPort &&
        _sameList(other.bypassDomains, bypassDomains) &&
        other.iranDirect == iranDirect &&
        other.cleanIp == cleanIp &&
        other.cleanIpHost == cleanIpHost;
  }

  @override
  int get hashCode => Object.hash(
    Object.hashAll(dnsServers),
    muxEnabled,
    muxConcurrency,
    sniffing,
    logLevel,
    fragment,
    routingMode,
    connectionMode,
    localProxyPort,
    Object.hashAll(bypassDomains),
    iranDirect,
    cleanIp,
    cleanIpHost,
  );

  static bool _sameList(List<String> a, List<String> b) {
    if (a.length != b.length) {
      return false;
    }
    for (int index = 0; index < a.length; index++) {
      if (a[index] != b[index]) {
        return false;
      }
    }
    return true;
  }
}

/// How the TLS handshake is broken up, if it is.
///
/// The three values are exactly what the core takes. Ranges rather than fixed
/// numbers on purpose: identical fragment sizes on every connection are
/// themselves a signature, and the point is to be harder to classify.
class FragmentSettings {
  const FragmentSettings({
    required this.enabled,
    required this.packets,
    required this.length,
    required this.interval,
  });

  final bool enabled;

  /// Which packets to split. `tlshello` splits only the client hello, which
  /// is the one carrying the server name and so the only one name-based
  /// inspection needs to read. `1-3` splits the first few packets of every
  /// connection: more disruptive to inspection, and more overhead.
  final String packets;

  /// Bytes per fragment, as a range.
  final String length;

  /// Milliseconds between fragments, as a range. The gap is what stops a
  /// middlebox simply reading the pieces back off the wire in one go.
  final String interval;

  static const FragmentSettings defaults = FragmentSettings(
    enabled: false,
    packets: 'tlshello',
    length: '100-200',
    interval: '10-20',
  );

  FragmentSettings copyWith({
    bool? enabled,
    String? packets,
    String? length,
    String? interval,
  }) {
    return FragmentSettings(
      enabled: enabled ?? this.enabled,
      packets: packets ?? this.packets,
      length: length ?? this.length,
      interval: interval ?? this.interval,
    );
  }

  @override
  bool operator ==(Object other) {
    return other is FragmentSettings &&
        other.enabled == enabled &&
        other.packets == packets &&
        other.length == length &&
        other.interval == interval;
  }

  @override
  int get hashCode => Object.hash(enabled, packets, length, interval);
}

final RegExp _rangePattern = RegExp(r'^[0-9]{1,5}(-[0-9]{1,5})?$');

/// Whether a value is something the core will accept as a fragment range.
///
/// Checked rather than trusted, because the core rejects the whole config
/// rather than the one field: a typo in this box does not produce a worse
/// tunnel, it produces no tunnel, reported as a failure to connect with
/// nothing naming the cause.
bool isValidFragmentRange(String value) {
  if (!_rangePattern.hasMatch(value)) {
    return false;
  }
  final List<int> parts = value
      .split('-')
      .map(int.parse)
      .toList(growable: false);
  if (parts.any((int part) => part <= 0)) {
    return false;
  }
  // A backwards range passes the pattern and is rejected by the core, which
  // is the worst combination: it looks right and fails later.
  return parts.length == 1 || parts[0] <= parts[1];
}

/// Whether a port is one a local proxy can listen on and an app can be
/// pointed at. Below 1024 needs privileges an app does not have.
bool isValidLocalProxyPort(int port) => port >= 1024 && port <= 65535;

/// How the connection reaches the apps that use it.
enum ConnectionMode {
  /// A VPN: every app's traffic, whether it knows or not.
  vpn,

  /// A SOCKS5 proxy on 127.0.0.1 for the apps pointed at it, and nothing
  /// for the rest. No VPN, so it can run beside another VPN app.
  localProxy,
}

/// Which connections the tunnel carries to the server.
enum RoutingMode {
  /// All of it. What a VPN does, and the only mode that gets past the filter.
  everything,

  /// Only services that refuse Iranian addresses, plus DNS; the rest leaves
  /// directly. For getting past sanctions, not censorship: filtered sites
  /// stay filtered, and in exchange nothing else pays for the detour.
  sanctionedOnly,
}

enum SniffingMode {
  /// What the app has always done: on for profiles with routing rules, off
  /// otherwise, so a profile with nothing to match skips the parse.
  whenRoutingNeedsIt,

  /// Always on. Needed if a rule is ever added that the profile does not
  /// itself declare.
  always,

  /// Never. The cheapest and the most private with respect to the core, at
  /// the cost of every domain-based rule silently matching nothing.
  never,
}

enum XrayLogLevel {
  debug,
  info,
  warning,
  error,
  none;

  /// What the core expects in `log.loglevel`.
  String get wireName => name;

  /// Whether choosing this records what was visited.
  ///
  /// Surfaced rather than hidden: `info` logs a line per connection
  /// including its destination, which turns the log screen into a browsing
  /// history on a device that may be inspected. Somebody may still want it
  /// while diagnosing something, and they should know what they are turning
  /// on.
  bool get recordsDestinations => this == debug || this == info;
}

abstract interface class AdvancedSettingsStore {
  AdvancedSettings read();
  Future<void> write(AdvancedSettings settings);
}

class SharedPreferencesAdvancedSettingsStore implements AdvancedSettingsStore {
  SharedPreferencesAdvancedSettingsStore(this._preferences);

  static const String _dnsKey = 'nebula.dns_servers';
  static const String _muxKey = 'nebula.mux_enabled';
  static const String _muxConcurrencyKey = 'nebula.mux_concurrency';
  static const String _sniffingKey = 'nebula.sniffing_mode';
  static const String _logLevelKey = 'nebula.log_level';
  static const String _fragmentKey = 'nebula.fragment_enabled';
  static const String _fragmentPacketsKey = 'nebula.fragment_packets';
  static const String _fragmentLengthKey = 'nebula.fragment_length';
  static const String _fragmentIntervalKey = 'nebula.fragment_interval';
  static const String _routingModeKey = 'nebula.routing_mode';
  static const String _connectionModeKey = 'nebula.connection_mode';
  static const String _localProxyPortKey = 'nebula.local_proxy_port';
  static const String _bypassDomainsKey = 'nebula.bypass_domains';
  static const String _iranDirectKey = 'nebula.iran_direct';
  static const String _cleanIpKey = 'nebula.clean_ip';
  static const String _cleanIpHostKey = 'nebula.clean_ip_host';

  final SharedPreferences _preferences;

  @override
  AdvancedSettings read() {
    const AdvancedSettings fallback = AdvancedSettings.defaults;
    return AdvancedSettings(
      // A missing key means never set, which reads as the default rather
      // than as an empty choice.
      dnsServers: _preferences.getStringList(_dnsKey) ?? fallback.dnsServers,
      muxEnabled: _preferences.getBool(_muxKey) ?? fallback.muxEnabled,
      muxConcurrency:
          _preferences.getInt(_muxConcurrencyKey) ?? fallback.muxConcurrency,
      sniffing: _readEnum(
        _preferences.getString(_sniffingKey),
        SniffingMode.values,
        fallback.sniffing,
      ),
      logLevel: _readEnum(
        _preferences.getString(_logLevelKey),
        XrayLogLevel.values,
        fallback.logLevel,
      ),
      routingMode: _readEnum(
        _preferences.getString(_routingModeKey),
        RoutingMode.values,
        fallback.routingMode,
      ),
      connectionMode: _readEnum(
        _preferences.getString(_connectionModeKey),
        ConnectionMode.values,
        fallback.connectionMode,
      ),
      localProxyPort: _readPort(_preferences.getInt(_localProxyPortKey)),
      // Validated coming out as well as going in, like the fragment ranges.
      bypassDomains:
          (_preferences.getStringList(_bypassDomainsKey) ?? const <String>[])
              .where((String d) => normalizeBypassEntry(d) == d)
              .toList(),
      iranDirect: _preferences.getBool(_iranDirectKey) ?? false,
      cleanIp: _readCleanIp(_preferences.getString(_cleanIpKey)),
      cleanIpHost: _preferences.getString(_cleanIpHostKey),
      fragment: FragmentSettings(
        enabled:
            _preferences.getBool(_fragmentKey) ?? fallback.fragment.enabled,
        packets:
            _preferences.getString(_fragmentPacketsKey) ??
            fallback.fragment.packets,
        // Validated coming out as well as going in: a value written by an
        // older build, or edited in the preferences file by hand, must not be
        // able to stop the app connecting at all.
        length: _readRange(
          _preferences.getString(_fragmentLengthKey),
          fallback.fragment.length,
        ),
        interval: _readRange(
          _preferences.getString(_fragmentIntervalKey),
          fallback.fragment.interval,
        ),
      ),
    );
  }

  /// Falls back rather than throwing on a value this build does not know.
  ///
  /// A downgrade, or a key written by a later version, must not leave the app
  /// unable to read its own settings and therefore unable to connect.
  static T _readEnum<T extends Enum>(
    String? stored,
    List<T> values,
    T fallback,
  ) {
    if (stored == null) {
      return fallback;
    }
    for (final T value in values) {
      if (value.name == stored) {
        return value;
      }
    }
    return fallback;
  }

  /// An IPv4 address or nothing: a value edited by hand must not reach the
  /// tunnel's config.
  static String? _readCleanIp(String? stored) {
    final InternetAddress? address = stored == null
        ? null
        : InternetAddress.tryParse(stored);
    return address != null && address.type == InternetAddressType.IPv4
        ? stored
        : null;
  }

  static int _readPort(int? stored) {
    return stored != null && isValidLocalProxyPort(stored)
        ? stored
        : AdvancedSettings.defaultLocalProxyPort;
  }

  static String _readRange(String? stored, String fallback) {
    if (stored == null || !isValidFragmentRange(stored)) {
      return fallback;
    }
    return stored;
  }

  @override
  Future<void> write(AdvancedSettings settings) async {
    // Clearing is a real operation: removing every custom resolver has to be
    // remembered, or the next launch restores the ones just deleted.
    if (settings.dnsServers.isEmpty) {
      await _preferences.remove(_dnsKey);
    } else {
      await _preferences.setStringList(_dnsKey, settings.dnsServers);
    }
    await _preferences.setBool(_muxKey, settings.muxEnabled);
    await _preferences.setInt(_muxConcurrencyKey, settings.muxConcurrency);
    await _preferences.setString(_sniffingKey, settings.sniffing.name);
    await _preferences.setString(_logLevelKey, settings.logLevel.name);
    await _preferences.setString(_routingModeKey, settings.routingMode.name);
    await _preferences.setString(
      _connectionModeKey,
      settings.connectionMode.name,
    );
    await _preferences.setInt(_localProxyPortKey, settings.localProxyPort);
    await _preferences.setStringList(_bypassDomainsKey, settings.bypassDomains);
    await _preferences.setBool(_iranDirectKey, settings.iranDirect);
    // The route name is kept on its own: it is learned while connected and
    // scanned for later, with nothing chosen yet.
    final String? cleanIp = settings.cleanIp;
    final String? cleanIpHost = settings.cleanIpHost;
    if (cleanIpHost == null) {
      await _preferences.remove(_cleanIpHostKey);
    } else {
      await _preferences.setString(_cleanIpHostKey, cleanIpHost);
    }
    if (cleanIp == null || cleanIpHost == null) {
      await _preferences.remove(_cleanIpKey);
    } else {
      await _preferences.setString(_cleanIpKey, cleanIp);
    }
    await _preferences.setBool(_fragmentKey, settings.fragment.enabled);
    await _preferences.setString(
      _fragmentPacketsKey,
      settings.fragment.packets,
    );
    await _preferences.setString(_fragmentLengthKey, settings.fragment.length);
    await _preferences.setString(
      _fragmentIntervalKey,
      settings.fragment.interval,
    );
  }
}

class InMemoryAdvancedSettingsStore implements AdvancedSettingsStore {
  AdvancedSettings _settings = AdvancedSettings.defaults;

  @override
  AdvancedSettings read() => _settings;

  @override
  Future<void> write(AdvancedSettings settings) async {
    _settings = settings;
  }
}

/// An entry of "Websites that skip the VPN": a website as
/// [normalizeBypassDomain] reads it, or an IP address or range as
/// [normalizeBypassAddress] does (roadmap 21: routing by IP/CIDR beside
/// routing by domain). Null for anything else.
String? normalizeBypassEntry(String input) =>
    normalizeBypassAddress(input) ?? normalizeBypassDomain(input);

/// Whether a stored entry is an address rather than a website.
bool isBypassAddress(String entry) => normalizeBypassAddress(entry) == entry;

/// An IP address or CIDR range, as Xray's `ip` rule takes it: `203.0.113.7`,
/// `203.0.113.0/24`, `2001:db8::/32`. Null for anything else, and for a
/// prefix of 0 -- the whole internet skipping the VPN is a typo, not a rule.
String? normalizeBypassAddress(String input) {
  final String text = input.trim();
  final List<String> parts = text.split('/');
  if (parts.length > 2) {
    return null;
  }
  final InternetAddress? address = InternetAddress.tryParse(parts.first);
  if (address == null) {
    return null;
  }
  // Lower-case: IPv6 hex keeps the case it was typed in.
  final String written = address.address.toLowerCase();
  if (parts.length == 1) {
    return written;
  }
  final int? prefix = int.tryParse(parts[1]);
  final int bits = address.type == InternetAddressType.IPv4 ? 32 : 128;
  if (prefix == null || prefix < 1 || prefix > bits) {
    return null;
  }
  return '$written/$prefix';
}

/// A website as a bypass rule names it: lower-case, without scheme, path,
/// port or a leading `www.`/`*.` -- `domain:` matches every subdomain, so
/// `bank.example` covers `www.bank.example`. Null for anything that is not
/// a host name with a dot in it.
String? normalizeBypassDomain(String input) {
  String host = input.trim().toLowerCase();
  final int scheme = host.indexOf('://');
  if (scheme >= 0) {
    host = host.substring(scheme + 3);
  }
  host = host.split('/').first.split('?').first;
  host = host.split(':').first;
  while (host.startsWith('*.') || host.startsWith('www.')) {
    host = host.substring(host.indexOf('.') + 1);
  }
  if (host.endsWith('.')) {
    host = host.substring(0, host.length - 1);
  }
  final RegExp label = RegExp(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$');
  final List<String> labels = host.split('.');
  return labels.length >= 2 &&
          host.length <= 253 &&
          labels.every(label.hasMatch) &&
          !RegExp(r'^[0-9]+$').hasMatch(labels.last)
      ? host
      : null;
}
