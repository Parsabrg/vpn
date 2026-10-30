import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/app_info.dart';
import '../../core/diagnostics/diagnostics_report.dart';
import '../../core/diagnostics/leak_test.dart';
import '../../core/diagnostics/packet_loss.dart';
import '../../core/diagnostics/speed_test.dart';
import '../../core/theme/color_tokens.dart';
import '../../core/wireguard/tunnel_controller.dart';
import '../../core/xray/local_proxy.dart';
import '../../l10n/app_localizations.dart';
import '../devices/devices_controller.dart';
import '../devices/devices_state.dart';

/// Where the tests go to measure the tunnel; null where this app's own
/// traffic already takes its path. See DevicesController.measurementRoute.
final measurementRouteProvider =
    Provider<({LocalProxy proxy, InternetAddress? resolver})?>((Ref ref) {
      ref.watch(devicesControllerProvider);
      return ref.read(devicesControllerProvider.notifier).measurementRoute;
    });

final leakTestProvider = Provider<LeakTest>((Ref ref) {
  final route = ref.watch(measurementRouteProvider);
  if (route == null) {
    return LeakTest();
  }
  final InternetAddress? resolver = route.resolver;
  return LeakTest(
    fetch: (Uri url) async {
      final ({int status, String body})? answer = await httpsThroughSocks(
        route.proxy,
        host: url.host,
        path: url.path,
      );
      return answer?.status == 200 ? answer!.body : null;
    },
    // The tunnel's own resolver, asked the way apps ask it: from here, a
    // lookup goes to the ISP's, which forges blocked names.
    lookup: resolver == null
        ? null
        : (String host) => lookupThroughSocks(route.proxy, resolver, host),
  );
});
final speedTestProvider = Provider<SpeedTest>((Ref ref) {
  final route = ref.watch(measurementRouteProvider);
  return SpeedTest(
    proxy: route == null ? null : httpProxyDirective(route.proxy),
  );
});
final packetLossTestProvider = Provider<PacketLossTest>(
  (Ref ref) =>
      PacketLossTest(through: ref.watch(measurementRouteProvider)?.proxy),
);

/// The connection as it is right now, the leak test, the speed test, and a
/// report to copy when asking for help (roadmap 77 and 78).
///
/// The tests run only when asked: a leak test makes a few requests to
/// Cloudflare and Akamai, which see the exit address -- the same address
/// every site does -- and a speed test moves up to 28 MB through Cloudflare.
class DiagnosticsScreen extends ConsumerStatefulWidget {
  const DiagnosticsScreen({super.key});

  @override
  ConsumerState<DiagnosticsScreen> createState() => _DiagnosticsScreenState();
}

class _DiagnosticsScreenState extends ConsumerState<DiagnosticsScreen> {
  LeakReport? _report;
  bool _running = false;
  SpeedReport? _speed;
  bool _measuringSpeed = false;
  LossReport? _loss;
  bool _measuringLoss = false;
  Duration? _handshakeAge;

  @override
  void initState() {
    super.initState();
    _readHandshake();
  }

  /// WireGuard's handshake, which only the tunnel can tell.
  Future<void> _readHandshake() async {
    final DevicesState state = ref.read(devicesControllerProvider);
    if (!state.tunnelEstablished ||
        state.activeProtocolCode != wireguardProtocolCode) {
      return;
    }
    final DateTime? latest = await ref
        .read(tunnelControllerProvider)
        .latestHandshake();
    if (mounted && latest != null && latest.millisecondsSinceEpoch > 0) {
      setState(() => _handshakeAge = DateTime.now().difference(latest));
    }
  }

  Future<void> _runLeakTest() async {
    setState(() => _running = true);
    await _readHandshake();
    final LeakReport report = await ref.read(leakTestProvider).run();
    if (mounted) {
      setState(() {
        _report = report;
        _running = false;
      });
    }
  }

  Future<void> _runSpeedTest() async {
    setState(() => _measuringSpeed = true);
    final SpeedReport speed = await ref.read(speedTestProvider).run();
    if (mounted) {
      setState(() {
        _speed = speed;
        _measuringSpeed = false;
      });
    }
  }

  Future<void> _runLossTest() async {
    setState(() => _measuringLoss = true);
    final LossReport loss = await ref.read(packetLossTestProvider).run();
    if (mounted) {
      setState(() {
        _loss = loss;
        _measuringLoss = false;
      });
    }
  }

  int? _lastTestMs(DevicesState state) {
    final String? profile = state.activeProfileCode;
    return profile == null
        ? null
        : state.delaysFor(state.connectedServerCode)[profile]?.milliseconds;
  }

  Future<void> _copyReport(DevicesState state) async {
    final AppText text = AppText.of(context);
    await Clipboard.setData(
      ClipboardData(
        text: diagnosticsReport(
          appVersion: kClientVersion,
          platform:
              '${Platform.operatingSystem} '
              '${Platform.operatingSystemVersion.split(' ').first}',
          connected: state.tunnelEstablished,
          localProxy: state.localProxy != null,
          server: state.tunnelEstablished
              ? state.selectedServer?.displayName
              : null,
          protocol: state.tunnelEstablished
              ? state.activeProfileCode ?? state.activeProtocolCode
              : null,
          lastTestMs: state.tunnelEstablished ? _lastTestMs(state) : null,
          handshakeAge: _handshakeAge,
          leaks: _report,
          speed: _speed,
          loss: _loss,
        ),
      ),
    );
    if (mounted) {
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(text.diagnosticsReportCopied)));
    }
  }

  @override
  Widget build(BuildContext context) {
    final NebulaPalette palette = context.palette;
    final AppText text = AppText.of(context);
    final DevicesState state = ref.watch(devicesControllerProvider);
    final bool connected = state.tunnelEstablished;
    final LeakReport? report = _report;
    final SpeedReport? speed = _speed;
    final LossReport? loss = _loss;
    final int? lastTestMs = _lastTestMs(state);

    return Scaffold(
      backgroundColor: palette.bg,
      appBar: AppBar(
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          onPressed: () => Navigator.of(context).maybePop(),
        ),
        title: Text(text.sectionDiagnostics),
        actions: <Widget>[
          IconButton(
            tooltip: text.diagnosticsCopyReport,
            icon: const Icon(Icons.copy_all),
            onPressed: () => _copyReport(state),
          ),
        ],
      ),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(20),
          children: <Widget>[
            _Heading(text.diagnosticsConnection),
            _Row(
              label: text.rowStatus,
              value: connected ? text.statusConnected : text.statusDisconnected,
              color: connected ? palette.blueText : palette.amberText,
            ),
            if (connected) ...<Widget>[
              _Row(
                label: text.rowServer,
                value: state.selectedServer?.displayName ?? '—',
                color: palette.textPrimary,
              ),
              _Row(
                label: text.rowProtocol,
                value:
                    state.activeProfileCode ?? state.activeProtocolCode ?? '—',
                color: palette.textPrimary,
              ),
              if (lastTestMs != null)
                _Row(
                  label: text.diagnosticsLastTest,
                  value: '$lastTestMs ms',
                  color: palette.textPrimary,
                ),
              if (_handshakeAge != null)
                _Row(
                  label: text.statusHandshake,
                  value: text.diagnosticsSecondsAgo(_handshakeAge!.inSeconds),
                  color: _handshakeAge! > const Duration(minutes: 3)
                      ? palette.amberText
                      : palette.textPrimary,
                ),
            ],
            const SizedBox(height: 28),
            _Heading(text.leakTest),
            Text(
              connected ? text.leakTestIntro : text.leakTestNotConnected,
              style: TextStyle(
                color: connected ? palette.textMuted : palette.amberText,
                height: 1.5,
              ),
            ),
            const SizedBox(height: 16),
            FilledButton(
              onPressed: _running ? null : _runLeakTest,
              child: _running
                  ? const SizedBox.square(
                      dimension: 18,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : Text(text.leakTestRun),
            ),
            if (report != null) ...<Widget>[
              const SizedBox(height: 16),
              _Row(
                label: text.leakTestExit,
                value: report.exitCountry == null
                    ? text.leakTestUnreachable
                    : '${report.exitCountry} · ${report.exitAddress}',
                color: report.exitCountry == null
                    ? palette.amberText
                    : palette.textPrimary,
              ),
              _Row(
                label: text.leakTestDns,
                value: switch (report.dns) {
                  DnsVerdict.clean => text.leakTestDnsClean,
                  DnsVerdict.forged => text.leakTestDnsForged,
                  DnsVerdict.failed => text.leakTestDnsFailed,
                },
                color: switch (report.dns) {
                  DnsVerdict.clean => palette.blueText,
                  DnsVerdict.forged => palette.redText,
                  DnsVerdict.failed => palette.amberText,
                },
              ),
              if (report.resolverNetwork != null)
                _Row(
                  label: text.leakTestResolver,
                  value: report.resolverNetwork!,
                  color: palette.textPrimary,
                ),
              _Row(
                label: text.leakTestIpv6,
                value: switch (report.ipv6) {
                  Ipv6Verdict.unavailable => text.leakTestIpv6Unavailable,
                  Ipv6Verdict.sameExit => text.leakTestIpv6Same,
                  Ipv6Verdict.leaking => text.leakTestIpv6Leaking(
                    report.ipv6Country ?? '?',
                  ),
                },
                color: report.ipv6 == Ipv6Verdict.leaking
                    ? palette.redText
                    : palette.blueText,
              ),
            ],
            const SizedBox(height: 28),
            _Heading(text.speedTest),
            Text(
              text.speedTestIntro,
              style: TextStyle(color: palette.textMuted, height: 1.5),
            ),
            const SizedBox(height: 16),
            FilledButton(
              onPressed: _measuringSpeed ? null : _runSpeedTest,
              child: _measuringSpeed
                  ? const SizedBox.square(
                      dimension: 18,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : Text(text.speedTestRun),
            ),
            if (speed != null) ...<Widget>[
              const SizedBox(height: 16),
              for (final (String label, double? mbps) in <(String, double?)>[
                (text.speedTestDownload, speed.downloadMbps),
                (text.speedTestUpload, speed.uploadMbps),
              ])
                _Row(
                  label: label,
                  value: mbps == null
                      ? text.speedTestFailed
                      : text.speedTestMbps(formatMbps(mbps)),
                  color: mbps == null ? palette.amberText : palette.textPrimary,
                ),
            ],
            const SizedBox(height: 28),
            _Heading(text.packetLoss),
            Text(
              text.packetLossIntro,
              style: TextStyle(color: palette.textMuted, height: 1.5),
            ),
            const SizedBox(height: 16),
            FilledButton(
              onPressed: _measuringLoss ? null : _runLossTest,
              child: _measuringLoss
                  ? const SizedBox.square(
                      dimension: 18,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : Text(text.packetLossRun),
            ),
            if (loss != null) ...<Widget>[
              const SizedBox(height: 16),
              _Row(
                label: text.packetLossLost,
                value: lossPercent(loss) == null
                    ? text.packetLossNotSent
                    : text.packetLossLostValue(
                        loss.sent - loss.received,
                        loss.sent,
                        lossPercent(loss)!,
                      ),
                color: (lossPercent(loss) ?? 100) > 2
                    ? palette.amberText
                    : palette.textPrimary,
              ),
              if (loss.median != null)
                _Row(
                  label: text.packetLossDelay,
                  value: text.packetLossDelayValue(
                    loss.median!.inMilliseconds,
                    loss.jitter?.inMilliseconds ?? 0,
                  ),
                  color: palette.textPrimary,
                ),
            ],
          ],
        ),
      ),
    );
  }
}

class _Heading extends StatelessWidget {
  const _Heading(this.text);

  final String text;

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.only(bottom: 8),
    child: Text(
      text,
      style: TextStyle(
        color: context.palette.textMax,
        fontWeight: FontWeight.w600,
      ),
    ),
  );
}

class _Row extends StatelessWidget {
  const _Row({required this.label, required this.value, required this.color});

  final String label;
  final String value;
  final Color color;

  @override
  Widget build(BuildContext context) {
    final NebulaPalette palette = context.palette;
    return Container(
      padding: const EdgeInsets.symmetric(vertical: 12),
      decoration: BoxDecoration(
        border: Border(bottom: BorderSide(color: palette.hairline)),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          SizedBox(
            width: 120,
            child: Text(label, style: TextStyle(color: palette.textMuted)),
          ),
          Expanded(
            child: SelectableText(value, style: TextStyle(color: color)),
          ),
        ],
      ),
    );
  }
}
