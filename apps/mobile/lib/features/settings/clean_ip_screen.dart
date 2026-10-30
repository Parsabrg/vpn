import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/cdn/clean_ip.dart';
import '../../core/settings/advanced_settings_controller.dart';
import '../../core/storage/advanced_settings_store.dart';
import '../../core/theme/color_tokens.dart';
import '../../core/xray/xray_config.dart';
import '../../l10n/app_localizations.dart';
import '../devices/devices_controller.dart';
import '../devices/devices_state.dart';

/// How many Cloudflare addresses one scan tries.
const int _scanSize = 100;

/// Finds a Cloudflare address that works from this network for the CDN
/// route, and uses it from the next connection (roadmap 11).
///
/// Scans only while disconnected: through the tunnel it would measure the
/// VPN server's network, not the person's. The route's name is learned
/// while connected through it, so a scan can follow a disconnect.
class CleanIpScreen extends ConsumerStatefulWidget {
  const CleanIpScreen({super.key});

  @override
  ConsumerState<CleanIpScreen> createState() => _CleanIpScreenState();
}

class _CleanIpScreenState extends ConsumerState<CleanIpScreen> {
  List<CleanIpResult>? _results;
  int? _done;
  bool _notCloudflare = false;

  @override
  void initState() {
    super.initState();
    final DevicesState devices = ref.read(devicesControllerProvider);
    final String? host = devices.xrayClient?.serverAddress;
    if (devices.tunnelEstablished &&
        host != null &&
        cdnTransports.contains(devices.xrayClient!.transport)) {
      Future<void>.microtask(
        () => ref
            .read(advancedSettingsControllerProvider.notifier)
            .rememberCdnHost(host),
      );
    }
  }

  Future<void> _scan(String host) async {
    setState(() {
      _done = 0;
      _results = null;
      _notCloudflare = false;
    });
    // Only a route through Cloudflare has edge addresses to choose from.
    bool onCloudflare = false;
    try {
      final List<InternetAddress> found = await InternetAddress.lookup(
        host,
        type: InternetAddressType.IPv4,
      );
      onCloudflare = found.any(
        (InternetAddress a) => isCloudflareAddress(a.address),
      );
    } on Object {
      onCloudflare = true; // Blocked lookups are exactly when a scan helps.
    }
    if (!onCloudflare) {
      if (mounted) {
        setState(() {
          _done = null;
          _notCloudflare = true;
        });
      }
      return;
    }
    final List<CleanIpResult> results = await scanCleanIps(
      host,
      sampleCloudflareAddresses(_scanSize),
      onProgress: (int done) {
        if (mounted) {
          setState(() => _done = done);
        }
      },
    );
    if (!mounted) {
      return;
    }
    setState(() {
      _done = null;
      _results = results.take(5).toList();
    });
    if (results.isNotEmpty) {
      await ref
          .read(advancedSettingsControllerProvider.notifier)
          .setCleanIp(results.first.ip);
    }
  }

  @override
  Widget build(BuildContext context) {
    final NebulaPalette palette = context.palette;
    final AppText text = AppText.of(context);
    final AdvancedSettings settings = ref.watch(
      advancedSettingsControllerProvider,
    );
    final bool connected = ref.watch(
      devicesControllerProvider.select((DevicesState s) => s.tunnelEstablished),
    );
    // On Android this app is outside its own Xray tunnel, so the scan already
    // tests the network itself; only a WireGuard tunnel (which carries this
    // app too) or a desktop one would put the VPN in the way.
    final bool scanInsideTunnel =
        connected &&
        !(defaultTargetPlatform == TargetPlatform.android &&
            ref.watch(
                  devicesControllerProvider.select(
                    (DevicesState s) => s.activeProtocolCode,
                  ),
                ) !=
                wireguardProtocolCode);
    final String? host = settings.cleanIpHost;
    final List<CleanIpResult>? results = _results;
    final int? done = _done;

    final String? blocker = scanInsideTunnel
        ? text.cleanIpDisconnectFirst
        : host == null
        ? text.cleanIpConnectOnce
        : null;

    return Scaffold(
      backgroundColor: palette.bg,
      appBar: AppBar(
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          onPressed: () => Navigator.of(context).maybePop(),
        ),
        title: Text(text.cleanIp),
      ),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(20),
          children: <Widget>[
            Text(
              text.cleanIpIntro,
              style: TextStyle(color: palette.textMuted, height: 1.5),
            ),
            const SizedBox(height: 16),
            _Line(
              label: text.cleanIp,
              value: settings.cleanIp ?? text.cleanIpAutomatic,
            ),
            if (host != null) _Line(label: 'CDN', value: host),
            const SizedBox(height: 16),
            if (blocker != null)
              Text(
                blocker,
                style: TextStyle(color: palette.amberText, height: 1.5),
              ),
            if (_notCloudflare)
              Text(
                text.cleanIpNotCloudflare,
                style: TextStyle(color: palette.amberText, height: 1.5),
              ),
            const SizedBox(height: 12),
            FilledButton(
              onPressed: blocker != null || done != null
                  ? null
                  : () => _scan(host!),
              child: Text(
                done != null
                    ? text.cleanIpScanning(done, _scanSize)
                    : text.cleanIpScan,
              ),
            ),
            if (settings.cleanIp != null)
              TextButton(
                onPressed: () => ref
                    .read(advancedSettingsControllerProvider.notifier)
                    .setCleanIp(null),
                child: Text(text.cleanIpUseAutomatic),
              ),
            if (results != null && results.isEmpty) ...<Widget>[
              const SizedBox(height: 12),
              Text(
                text.cleanIpNoneFound,
                style: TextStyle(color: palette.amberText, height: 1.5),
              ),
            ],
            if (results != null && results.isNotEmpty) ...<Widget>[
              const SizedBox(height: 16),
              for (final CleanIpResult r in results)
                ListTile(
                  contentPadding: EdgeInsets.zero,
                  title: Text(
                    r.ip,
                    style: TextStyle(color: palette.textPrimary),
                  ),
                  trailing: Text(
                    r.ip == settings.cleanIp
                        ? '${r.milliseconds} ms · ${text.cleanIpInUse}'
                        : '${r.milliseconds} ms',
                    style: TextStyle(
                      color: r.ip == settings.cleanIp
                          ? palette.blueText
                          : palette.textMuted,
                    ),
                  ),
                  onTap: () => ref
                      .read(advancedSettingsControllerProvider.notifier)
                      .setCleanIp(r.ip),
                ),
              const SizedBox(height: 8),
              Text(
                text.cleanIpAppliesNext,
                style: TextStyle(color: palette.textMuted, height: 1.5),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

class _Line extends StatelessWidget {
  const _Line({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final NebulaPalette palette = context.palette;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        children: <Widget>[
          SizedBox(
            width: 140,
            child: Text(label, style: TextStyle(color: palette.textMuted)),
          ),
          Expanded(
            child: SelectableText(
              value,
              style: TextStyle(color: palette.textPrimary),
            ),
          ),
        ],
      ),
    );
  }
}
