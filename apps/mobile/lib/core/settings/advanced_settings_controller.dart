import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../storage/advanced_settings_store.dart';
import '../storage/storage_providers.dart';

/// Holds the core-level settings and persists every change.
///
/// State moves before the write is awaited, the same trade the protection
/// toggles make: the control moves under the finger rather than after a disk
/// round trip, at the cost of the UI being ahead of storage if a write fails.
class AdvancedSettingsController extends Notifier<AdvancedSettings> {
  @override
  AdvancedSettings build() {
    return ref.watch(advancedSettingsStoreProvider).read();
  }

  Future<void> setDnsServers(List<String> servers) {
    // Cleaned at the edge rather than at every reader: what is stored is
    // what will be written into the config, so a stray blank entry here
    // becomes an empty DNS server the core either rejects or ignores.
    final List<String> cleaned = servers
        .map((String entry) => entry.trim())
        .where((String entry) => entry.isNotEmpty)
        .toList();
    return _write(state.copyWith(dnsServers: cleaned));
  }

  Future<void> setMuxEnabled({required bool enabled}) {
    return _write(state.copyWith(muxEnabled: enabled));
  }

  Future<void> setMuxConcurrency(int concurrency) {
    // Bounded here so an out-of-range value cannot reach the config. Xray
    // rejects the whole file rather than the one field, so a bad number does
    // not produce a worse tunnel -- it produces no tunnel, reported as a
    // failure to connect with nothing naming the cause.
    return _write(state.copyWith(muxConcurrency: concurrency.clamp(1, 128)));
  }

  Future<void> setSniffing(SniffingMode mode) {
    return _write(state.copyWith(sniffing: mode));
  }

  Future<void> setLogLevel(XrayLogLevel level) {
    return _write(state.copyWith(logLevel: level));
  }

  Future<void> setFragmentEnabled({required bool enabled}) {
    return _write(
      state.copyWith(fragment: state.fragment.copyWith(enabled: enabled)),
    );
  }

  Future<void> setFragmentPackets(String packets) {
    return _write(
      state.copyWith(fragment: state.fragment.copyWith(packets: packets)),
    );
  }

  /// Rejected rather than stored when it is not something the core accepts.
  /// Returns whether it was taken, so the field can say so.
  ///
  /// The alternative -- storing it and finding out at connect time -- turns a
  /// typo into a tunnel that will not start, reported as a failure to connect
  /// with nothing pointing back at this box.
  Future<bool> setFragmentLength(String length) async {
    if (!isValidFragmentRange(length)) {
      return false;
    }
    await _write(
      state.copyWith(fragment: state.fragment.copyWith(length: length)),
    );
    return true;
  }

  Future<bool> setFragmentInterval(String interval) async {
    if (!isValidFragmentRange(interval)) {
      return false;
    }
    await _write(
      state.copyWith(fragment: state.fragment.copyWith(interval: interval)),
    );
    return true;
  }

  /// The CDN route's name, learned from a connection through it. A new
  /// name forgets the address chosen for the old one.
  Future<void> rememberCdnHost(String host) {
    if (state.cleanIpHost == host) {
      return Future<void>.value();
    }
    return _write(state.copyWith(cleanIpHost: () => host, cleanIp: () => null));
  }

  /// The Cloudflare address to dial the CDN route at; null for automatic.
  Future<void> setCleanIp(String? ip) {
    return _write(state.copyWith(cleanIp: () => ip));
  }

  Future<void> setIranDirect({required bool enabled}) {
    return _write(state.copyWith(iranDirect: enabled));
  }

  /// Adds a website that skips the VPN. Returns false for anything that is
  /// not a host name, so the field can say so; an entry already listed is
  /// taken and left as it was.
  Future<bool> addBypassDomain(String input) async {
    final String? domain = normalizeBypassEntry(input);
    if (domain == null) {
      return false;
    }
    if (!state.bypassDomains.contains(domain)) {
      await _write(
        state.copyWith(bypassDomains: <String>[...state.bypassDomains, domain]),
      );
    }
    return true;
  }

  Future<void> removeBypassDomain(String domain) {
    return _write(
      state.copyWith(
        bypassDomains: <String>[
          for (final String d in state.bypassDomains)
            if (d != domain) d,
        ],
      ),
    );
  }

  Future<void> setRoutingMode(RoutingMode mode) {
    return _write(state.copyWith(routingMode: mode));
  }

  Future<void> setConnectionMode(ConnectionMode mode) {
    return _write(state.copyWith(connectionMode: mode));
  }

  /// Rejected rather than stored when no app could be pointed at it.
  /// Returns whether it was taken, so the field can say so.
  Future<bool> setLocalProxyPort(int port) async {
    if (!isValidLocalProxyPort(port)) {
      return false;
    }
    await _write(state.copyWith(localProxyPort: port));
    return true;
  }

  /// Resets the tuning, not the choices that live in Settings: what is
  /// routed, and whether this is a VPN or a local proxy.
  Future<void> restoreDefaults() => _write(
    AdvancedSettings.defaults.copyWith(
      routingMode: state.routingMode,
      connectionMode: state.connectionMode,
      localProxyPort: state.localProxyPort,
    ),
  );

  Future<void> _write(AdvancedSettings next) async {
    state = next;
    await ref.read(advancedSettingsStoreProvider).write(next);
  }
}

final NotifierProvider<AdvancedSettingsController, AdvancedSettings>
advancedSettingsControllerProvider =
    NotifierProvider<AdvancedSettingsController, AdvancedSettings>(
      AdvancedSettingsController.new,
    );
