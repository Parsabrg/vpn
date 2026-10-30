import 'dart:async';
import 'dart:convert';
import 'dart:io';

import '../tunnel/tunnel_traffic.dart';
import 'linux_tunnel_config.dart';
import 'linux_vpn_supervisor.dart';
import 'windows_tunnel_config.dart';
import 'xray_tunnel_controller.dart';

/// Linux implementation for Xray-backed profiles: the bundled xray with its
/// own TUN, set up by a root helper started through pkexec. See
/// [linuxVpnSupervisorScript] and [linuxXrayTunConfig].
class LinuxXrayTunnelController implements XrayTunnelController {
  LinuxXrayTunnelController({LinuxXrayRuntime? runtime})
    : _runtime = runtime ?? LinuxXrayRuntime();

  final LinuxXrayRuntime _runtime;

  @override
  Future<bool> requestPermission() async => true;

  @override
  Future<void> connect(
    String xrayConfigJson, {
    List<String> excludedPackages = const <String>[],
    List<String>? routes,
    String sessionName = 'Nebula',
    bool notificationShowsSpeed = true,
    String disconnectLabel = 'Disconnect',
    bool proxyOnly = false,
    bool killSwitch = false,
  }) => _runtime.start(
    xrayConfigJson,
    proxyOnly: proxyOnly,
    killSwitch: killSwitch,
  );

  @override
  Future<void> disconnect() => _runtime.stop();

  @override
  Future<void> attach() => _runtime.attach();

  @override
  Stream<TunnelTraffic> get traffic => _runtime.traffic;

  @override
  Future<List<String>> logs() => _runtime.logs();

  @override
  Future<bool> clearLogs() => _runtime.clearLogs();

  @override
  Future<bool?> engineRunning() => _runtime.engineRunning();

  @override
  Future<int?> measureDelay(String config, {required String url}) =>
      _runtime.measureDelay(config, url: url);

  @override
  Future<double?> measureDownload(String config, {required String url}) =>
      _runtime.measureDownload(config, url: url);
}

class LinuxXrayRuntime {
  /// [runtimeDirectory] holds xray and its geo files; the app bundle's by
  /// default.
  LinuxXrayRuntime({String? runtimeDirectory})
    : _runtimeDirectory =
          runtimeDirectory ??
          '${File(Platform.resolvedExecutable).parent.path}/data/flutter_assets/assets/linux_runtime';

  final String _runtimeDirectory;
  Directory? _state;
  int? _localXrayPid;
  final List<String> _logs = <String>[];
  final StreamController<TunnelTraffic> _trafficController =
      StreamController<TunnelTraffic>.broadcast();
  Timer? _trafficTimer;

  Stream<TunnelTraffic> get traffic => _trafficController.stream;

  Future<void> attach() async {
    if (await linuxTunnelUp()) {
      _startTrafficMonitoring();
    }
  }

  Future<void> start(
    String encodedConfig, {
    required bool proxyOnly,
    bool killSwitch = false,
  }) async {
    await stop();
    final Map<String, dynamic> source =
        jsonDecode(encodedConfig) as Map<String, dynamic>;
    final String? hysteriaYaml = source['nebulaHysteriaConfig'] as String?;
    final Directory state = await linuxPrivateTemp('nebula-tun-');
    _state = state;
    try {
      if (hysteriaYaml != null) {
        await _startHysteria(
          source,
          hysteriaYaml,
          state,
          proxyOnly: proxyOnly,
          killSwitch: killSwitch,
        );
        return;
      }
      final String xray = await _runtimeBinary('xray');
      final File configFile = File('${state.path}/xray.json');
      if (proxyOnly) {
        await configFile.writeAsString(jsonEncode(source));
        _localXrayPid = await _startQuiet(xray, <String>[
          'run',
          '-c',
          configFile.path,
        ]);
        return;
      }
      final String? host = _upstreamAddress(source);
      final String? upstreamIp =
          pinnedUpstream(source, host) ?? await _resolveIpv4(host);
      if (host == null || upstreamIp == null) {
        throw StateError('Linux could not resolve the VPN server address.');
      }
      final List<String> resolvers = windowsTunnelDnsServers(source);
      await configFile.writeAsString(
        jsonEncode(
          linuxXrayTunConfig(
            windowsXrayPinnedUpstream(source, host, upstreamIp),
            resolvers,
          ),
        ),
      );
      await startLinuxVpnHelper(
        engine: xray,
        config: configFile,
        dnsServers: resolvers,
        killSwitch: killSwitch,
      );
      _startTrafficMonitoring();
    } catch (_) {
      await stop();
      rethrow;
    }
  }

  /// Hysteria2 runs its own engine, as on Windows; the helper routes its
  /// TUN as it does Xray's, the server's resolved address left out.
  Future<void> _startHysteria(
    Map<String, dynamic> source,
    String yaml,
    Directory state, {
    required bool proxyOnly,
    required bool killSwitch,
  }) async {
    final String hysteria = await _runtimeBinary('hysteria');
    final File configFile = File('${state.path}/hysteria.yaml');
    if (proxyOnly) {
      await configFile.writeAsString(yaml);
      _localXrayPid = await _startQuiet(hysteria, <String>[
        'client',
        '-c',
        configFile.path,
      ]);
      return;
    }
    final String? upstreamIp = await _resolveIpv4(_upstreamAddress(source));
    if (upstreamIp == null) {
      throw StateError('Linux could not resolve the VPN server address.');
    }
    await configFile.writeAsString(
      windowsHysteriaFullTunnelConfig(
        yaml,
        upstreamIp,
        interfaceName: linuxTunnelInterface,
        platform: 'Linux',
        route: false,
      ),
    );
    await startLinuxVpnHelper(
      engine: hysteria,
      config: configFile,
      dnsServers: windowsTunnelDnsServers(source),
      killSwitch: killSwitch,
    );
    _startTrafficMonitoring();
  }

  Future<void> stop() async {
    _trafficTimer?.cancel();
    _trafficTimer = null;
    final int? local = _localXrayPid;
    _localXrayPid = null;
    if (local != null) {
      Process.killPid(local);
    }
    final Directory? state = _state;
    _state = null;
    if (state != null) {
      await stopLinuxVpnHelper(state);
    }
  }

  Future<bool?> engineRunning() async {
    final Directory? state = _state;
    if (state == null) {
      return null;
    }
    final int? enginePid =
        _localXrayPid ??
        int.tryParse(
          await File(
            '${linuxSessionOutputs(state.path)}/xray.pid',
          ).readAsString().catchError((Object _) => ''),
        );
    return enginePid == null ? null : Directory('/proc/$enginePid').exists();
  }

  /// A real request through [config]'s outbound, as on Windows: a local
  /// xray of its own with an HTTP inbound, no root needed.
  Future<int?> measureDelay(String config, {required String url}) =>
      _withProbe<int?>(config, -1, (HttpClient client) async {
        final Stopwatch watch = Stopwatch()..start();
        final int status = await () async {
          final HttpClientResponse response = await (await client.getUrl(
            Uri.parse(url),
          )).close();
          await response.drain<void>();
          return response.statusCode;
        }().timeout(const Duration(seconds: 10));
        return status < 400 ? watch.elapsedMilliseconds : -1;
      });

  /// Megabits a second over a download of [url] through [config]'s
  /// outbound, as v2rayN's speed test: what arrived in at most ten seconds,
  /// so a route that stalls part way reads slow rather than failed.
  Future<double?> measureDownload(String config, {required String url}) =>
      _withProbe<double?>(config, -1, (HttpClient client) async {
        final Stopwatch watch = Stopwatch()..start();
        int got = 0;
        try {
          final HttpClientResponse response = await (await client.getUrl(
            Uri.parse(url),
          )).close().timeout(const Duration(seconds: 10));
          await for (final List<int> chunk in response.timeout(
            const Duration(seconds: 5),
          )) {
            got += chunk.length;
            if (watch.elapsed > const Duration(seconds: 10)) {
              break;
            }
          }
        } on Object {
          // What arrived before the stall still counts.
        }
        final double seconds = watch.elapsedMicroseconds / 1e6;
        return got == 0 || seconds == 0 ? -1 : got * 8 / seconds / 1e6;
      });

  Future<T> _withProbe<T>(
    String config,
    T failed,
    Future<T> Function(HttpClient client) use,
  ) async {
    final Directory state = await linuxPrivateTemp('nebula-probe-');
    int? probePid;
    try {
      final Map<String, dynamic> source =
          jsonDecode(config) as Map<String, dynamic>;
      if (source.containsKey('nebulaHysteriaConfig')) {
        // Not measurable here (both callers' T is nullable): unknown, not
        // failed.
        return null as T;
      }
      final ServerSocket probe = await ServerSocket.bind(
        InternetAddress.loopbackIPv4,
        0,
      );
      final int port = probe.port;
      await probe.close();
      final File file = File('${state.path}/xray.json');
      await file.writeAsString(
        jsonEncode(<String, dynamic>{
          ...source,
          'inbounds': <Map<String, dynamic>>[
            <String, dynamic>{
              'listen': '127.0.0.1',
              'port': port,
              'protocol': 'http',
            },
          ],
        }),
      );
      probePid = await _startQuiet(await _runtimeBinary('xray'), <String>[
        'run',
        '-c',
        file.path,
      ]);
      if (!await _listening(port)) {
        return failed;
      }
      final HttpClient client = HttpClient()
        ..findProxy = ((Uri _) => 'PROXY 127.0.0.1:$port')
        ..connectionTimeout = const Duration(seconds: 10);
      try {
        return await use(client);
      } finally {
        client.close(force: true);
      }
    } on Object {
      return failed;
    } finally {
      if (probePid != null) {
        Process.killPid(probePid);
      }
      try {
        await state.delete(recursive: true);
      } on FileSystemException {
        // Swept at the next start.
      }
    }
  }

  Future<List<String>> logs() async => List<String>.unmodifiable(_logs);

  Future<bool> clearLogs() async {
    _logs.clear();
    return true;
  }

  void _startTrafficMonitoring() {
    _trafficTimer?.cancel();
    _trafficTimer = Timer.periodic(const Duration(seconds: 1), (_) async {
      final TunnelTraffic? reading = await linuxTunnelTraffic();
      if (reading != null && !_trafficController.isClosed) {
        _trafficController.add(reading);
      }
    });
  }

  /// The bundled engine. Flutter copies assets without their executable
  /// bit, so the bit is set here when the bundle allows it.
  Future<String> _runtimeBinary(String name) async {
    final String path = '$_runtimeDirectory/$name';
    if (!await File(path).exists()) {
      throw StateError(
        'Nebula runtime file "$name" is missing. Reinstall the app.',
      );
    }
    await Process.run('chmod', <String>['u+x', path]);
    return path;
  }

  static Future<int> _startQuiet(String executable, List<String> args) async {
    final Process process = await Process.start(
      executable,
      args,
      workingDirectory: File(executable).parent.path,
      mode: ProcessStartMode.detached,
    );
    return process.pid;
  }

  static Future<bool> _listening(int port) async {
    final DateTime deadline = DateTime.now().add(const Duration(seconds: 10));
    while (DateTime.now().isBefore(deadline)) {
      try {
        final Socket socket = await Socket.connect(
          InternetAddress.loopbackIPv4,
          port,
          timeout: const Duration(milliseconds: 300),
        );
        socket.destroy();
        return true;
      } on SocketException {
        await Future<void>.delayed(const Duration(milliseconds: 200));
      }
    }
    return false;
  }

  static String? _upstreamAddress(Map<String, dynamic> source) {
    try {
      final List<dynamic> outbounds = source['outbounds'] as List<dynamic>;
      final Map<String, dynamic> settings =
          (outbounds.first as Map<String, dynamic>)['settings']
              as Map<String, dynamic>;
      // VLESS names its server under vnext, Hysteria2 under servers.
      final List<dynamic> servers =
          (settings['vnext'] ?? settings['servers']) as List<dynamic>;
      return (servers.first as Map<String, dynamic>)['address'] as String?;
    } on Object {
      return null;
    }
  }

  static Future<String?> _resolveIpv4(String? host) async {
    if (host == null || host.isEmpty) return null;
    if (RegExp(r'^\d{1,3}(\.\d{1,3}){3}$').hasMatch(host)) return host;
    try {
      final List<InternetAddress> addresses = await InternetAddress.lookup(
        host,
        type: InternetAddressType.IPv4,
      );
      return addresses.isEmpty ? null : addresses.first.address;
    } on SocketException {
      return null;
    }
  }
}
