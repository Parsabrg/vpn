import 'dart:async';
import 'dart:convert';
import 'dart:io';

import '../routing/tunnel_routes.dart';
import '../tunnel/tunnel_traffic.dart';
import 'windows_network_monitor.dart';
import 'windows_system_proxy.dart';
import 'windows_tunnel_config.dart';
import 'windows_vpn_supervisor.dart';
import 'xray_tunnel_controller.dart';

/// Windows implementation for Xray-backed profiles.
///
/// The selected engine owns a Wintun interface and system routes. A hidden
/// helper handles one connect-time elevation and reverts session DNS on exit.
/// The app never passes a server supplied command line to either process.
class WindowsXrayTunnelController implements XrayTunnelController {
  WindowsXrayTunnelController({WindowsXrayRuntime? runtime})
    : _runtime = runtime ?? WindowsXrayRuntime();

  final WindowsXrayRuntime _runtime;

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
    // Routes that leave anything out are "Allow local network" (see
    // tunnel_routes.dart); Windows keeps its routes and lets Xray send
    // those addresses out directly instead.
    localNetworkDirect: routes != null && !routes.contains(kAllIPv4.single),
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

/// A deliberately narrow process boundary. Only binaries shipped inside this
/// app can run, only generated config paths are passed, and the UAC command is
/// a fixed PowerShell script written by this class.
class WindowsXrayRuntime {
  Directory? _stateDirectory;
  int? _xraySupervisorPid;
  int? _xrayPid;
  int? _hysteriaPid;
  final List<String> _logs = <String>[];

  final StreamController<TunnelTraffic> _trafficController =
      StreamController<TunnelTraffic>.broadcast();
  Timer? _trafficTimer;

  Stream<TunnelTraffic> get traffic => _trafficController.stream;

  Future<void> attach() async {
    if (await WindowsNetworkMonitor.isAdapterUp()) {
      _startTrafficMonitoring();
    }
  }

  Future<void> start(
    String encodedConfig, {
    required bool proxyOnly,
    bool killSwitch = false,
    bool localNetworkDirect = false,
  }) async {
    await stop();
    final Directory state = await Directory.systemTemp.createTemp(
      'nebula-tun-',
    );
    _stateDirectory = state;
    try {
      final Map<String, dynamic> source =
          jsonDecode(encodedConfig) as Map<String, dynamic>;
      final bool isHysteria = source.containsKey('nebulaHysteriaConfig');

      // Always resolve upstream server address to IPv4 first.
      // This is crucial to prevent the routing loop on Windows.
      final String? upstreamAddress = _upstreamAddress(source, isHysteria);
      final String? upstreamIp =
          pinnedUpstream(source, upstreamAddress) ??
          await _resolveIpv4(upstreamAddress);
      if (upstreamIp == null) {
        throw StateError('Windows could not resolve the VPN server address.');
      }

      final List<String> dnsServers = windowsTunnelDnsServers(source);

      if (isHysteria) {
        final String? hysteria = _runtimeBinaryOrNull('hysteria.exe');
        if (hysteria == null) {
          throw StateError('The bundled Hysteria2 runtime is missing.');
        }
        final File hysteriaConfig = File('${state.path}\\hysteria.yaml');
        if (!proxyOnly) {
          await hysteriaConfig.writeAsString(
            windowsHysteriaFullTunnelConfig(
              source['nebulaHysteriaConfig'] as String,
              upstreamIp,
            ),
          );
          _xraySupervisorPid = await _startElevatedSupervisor(
            engine: hysteria,
            arguments: <String>['client', '-c', hysteriaConfig.path],
            state: state.path,
            upstreamIp: upstreamIp,
            dnsServers: dnsServers,
            isXray: false,
            killSwitch: killSwitch,
          );
          if (!await _nativeTunIsReady(state)) {
            throw StateError(
              'Windows did not finish configuring the VPN routes.',
            );
          }
          _startTrafficMonitoring();
          return;
        }

        await hysteriaConfig.writeAsString(
          source['nebulaHysteriaConfig'] as String,
        );
        _hysteriaPid = await _startHidden(hysteria, <String>[
          'client',
          '-c',
          hysteriaConfig.path,
        ]);
        final int? proxyPort = _extractLocalProxyPort(source);
        if (proxyPort != null) {
          await WindowsSystemProxy.enable(proxyPort);
        }
        await Future<void>.delayed(const Duration(milliseconds: 750));
        if (!await _processIsRunning(_hysteriaPid!)) {
          throw StateError('Windows Hysteria2 stopped before connecting.');
        }
        return;
      }

      final String xray = _runtimeBinary('xray.exe');
      final Map<String, dynamic> config = proxyOnly
          ? source
          : windowsXrayPinnedUpstream(
              _xrayTunConfig(source, proxyOnly, localNetworkDirect),
              upstreamAddress!,
              upstreamIp,
            );
      final File configFile = File('${state.path}\\xray.json');
      await configFile.writeAsString(jsonEncode(config));

      if (proxyOnly) {
        _xrayPid = await _startHidden(xray, <String>[
          'run',
          '-c',
          configFile.path,
        ]);
        final int? proxyPort = _extractLocalProxyPort(source);
        if (proxyPort != null) {
          await WindowsSystemProxy.enable(proxyPort);
        }
        return;
      }

      _xraySupervisorPid = await _startElevatedSupervisor(
        engine: xray,
        arguments: <String>['run', '-c', configFile.path],
        state: state.path,
        upstreamIp: upstreamIp,
        dnsServers: dnsServers,
        isXray: true,
        killSwitch: killSwitch,
      );

      if (!await _nativeTunIsReady(state)) {
        throw StateError('Windows did not finish configuring the VPN routes.');
      }
      if (!await _tunAdapterIsUp()) {
        throw StateError('Windows did not create the Nebula VPN adapter.');
      }
      _startTrafficMonitoring();
    } catch (_) {
      await stop();
      rethrow;
    }
  }

  Future<void> stop() async {
    _trafficTimer?.cancel();
    _trafficTimer = null;
    await WindowsSystemProxy.disable();

    final int? localXrayPid = _xrayPid;
    _xrayPid = null;
    if (localXrayPid != null) {
      await _stopHidden(localXrayPid);
    }
    final int? pid = _xraySupervisorPid;
    _xraySupervisorPid = null;
    bool canDeleteState = true;
    if (pid != null) {
      try {
        canDeleteState = await _stopElevated(pid, _stateDirectory?.path);
      } on Object catch (error) {
        _logs.add('Unable to stop VPN supervisor: $error');
      }
    }
    final int? hysteriaPid = _hysteriaPid;
    _hysteriaPid = null;
    if (hysteriaPid != null) {
      await _stopHidden(hysteriaPid);
    }
    final Directory? state = _stateDirectory;
    _stateDirectory = null;
    if (canDeleteState && state != null && await state.exists()) {
      try {
        await state.delete(recursive: true);
      } catch (_) {}
    }
  }

  /// A profile's real delay, as the Android plugin measures it: an xray.exe
  /// of its own with the probe's outbound, a request through it, timed.
  /// Hysteria2's probe carries the reference client's config, which is
  /// started first and measured through, as on Android.
  ///
  /// ponytail: the local HTTP inbound has no password, unlike the tunnel's,
  /// because it lives for one request on a random loopback port. Lock it like
  /// the tunnel's if probes ever run for longer.
  Future<int?> measureDelay(String config, {required String url}) =>
      _withProbe<int?>(config, -1, (HttpClient client) async {
        final Stopwatch watch = Stopwatch()..start();
        // One deadline for the whole request. The proxy's own handshake
        // happens before any response, and against a server that never
        // answers it waited forever with the probe's xray.exe left running.
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
    final Directory state = await Directory.systemTemp.createTemp(
      'nebula-probe-',
    );
    final List<int> pids = <int>[];
    try {
      final Map<String, dynamic> source =
          jsonDecode(config) as Map<String, dynamic>;
      final String? hysteriaYaml =
          source.remove('nebulaHysteriaConfig') as String?;
      final int? hysteriaPort = source.remove('nebulaHysteriaPort') as int?;
      if (hysteriaYaml != null) {
        final File yaml = File('${state.path}\\hysteria.yaml');
        await yaml.writeAsString(hysteriaYaml);
        pids.add(
          await _startHidden(_runtimeBinary('hysteria.exe'), <String>[
            'client',
            '-c',
            yaml.path,
          ]),
        );
        if (hysteriaPort == null || !await _listening(hysteriaPort)) {
          return failed;
        }
      }
      final ServerSocket probe = await ServerSocket.bind(
        InternetAddress.loopbackIPv4,
        0,
      );
      final int port = probe.port;
      await probe.close();
      final File xrayConfig = File('${state.path}\\xray.json');
      await xrayConfig.writeAsString(
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
      pids.add(
        await _startHidden(_runtimeBinary('xray.exe'), <String>[
          'run',
          '-c',
          xrayConfig.path,
        ]),
      );
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
      for (final int pid in pids) {
        await _stopHidden(pid);
      }
      try {
        await state.delete(recursive: true);
      } catch (_) {}
    }
  }

  /// Whether something accepts on this loopback port within ten seconds.
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

  Future<List<String>> logs() async => List<String>.unmodifiable(_logs);
  Future<bool> clearLogs() async {
    _logs.clear();
    return true;
  }

  void _startTrafficMonitoring() {
    _trafficTimer?.cancel();
    _trafficTimer = Timer.periodic(const Duration(seconds: 1), (_) async {
      final TunnelTraffic? reading = await WindowsNetworkMonitor.readTraffic();
      if (reading != null && !_trafficController.isClosed) {
        _trafficController.add(reading);
      }
    });
  }

  String _runtimeBinary(String name) =>
      _runtimeBinaryOrNull(name) ??
      (throw StateError(
        'Nebula runtime file "$name" is missing. Reinstall the app.',
      ));

  String? _runtimeBinaryOrNull(String name) {
    final String path =
        '${File(Platform.resolvedExecutable).parent.path}\\data\\flutter_assets\\assets\\windows_runtime\\$name';
    return File(path).existsSync() ? path : null;
  }

  Map<String, dynamic> _xrayTunConfig(
    Map<String, dynamic> config,
    bool proxyOnly,
    bool localNetworkDirect,
  ) => proxyOnly
      ? config
      : windowsXrayTunConfig(config, localNetworkDirect: localNetworkDirect);

  String? _upstreamAddress(Map<String, dynamic> source, bool isHysteria) {
    try {
      final List<dynamic> outbounds = source['outbounds'] as List<dynamic>;
      final Map<String, dynamic> settings =
          (outbounds.first as Map<String, dynamic>)['settings']
              as Map<String, dynamic>;
      if (isHysteria) {
        final List<dynamic> servers = settings['servers'] as List<dynamic>;
        return (servers.first as Map<String, dynamic>)['address'] as String?;
      }
      final List<dynamic> vnext = settings['vnext'] as List<dynamic>;
      return (vnext.first as Map<String, dynamic>)['address'] as String?;
    } on Object {
      return null;
    }
  }

  int? _extractLocalProxyPort(Map<String, dynamic> source) {
    try {
      final List<dynamic>? inbounds = source['inbounds'] as List<dynamic>?;
      if (inbounds != null && inbounds.isNotEmpty) {
        final Map<String, dynamic> first =
            inbounds.first as Map<String, dynamic>;
        final dynamic port = first['port'];
        if (port is int) return port;
      }
    } catch (_) {}
    return null;
  }

  Future<String?> _resolveIpv4(String? host) async {
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

  Future<int> _startElevatedSupervisor({
    required String engine,
    required List<String> arguments,
    required String state,
    required String upstreamIp,
    required List<String> dnsServers,
    required bool isXray,
    bool killSwitch = false,
  }) async {
    final File runner = File('$state\\elevated-supervisor.ps1');
    await runner.writeAsString(windowsVpnSupervisorScript);
    final String invocation = <String>[
      '&',
      windowsPowerShellLiteral(runner.path),
      windowsPowerShellLiteral(engine),
      windowsPowerShellLiteral(jsonEncode(arguments)),
      windowsPowerShellLiteral(state),
      windowsPowerShellLiteral(upstreamIp),
      windowsPowerShellLiteral(jsonEncode(dnsServers)),
      '$pid',
      isXray ? "'true'" : "'false'",
      killSwitch ? "'true'" : "'false'",
      windowsPowerShellLiteral(
        jsonEncode(<String>[
          if (killSwitch) ...windowsKillSwitchBlockedIpv4(upstreamIp),
          if (killSwitch) ...windowsKillSwitchBlockedIpv6,
        ]),
      ),
    ].join(' ');
    final String encoded = windowsEncodedCommand(invocation);
    final String launch =
        '''
\$ErrorActionPreference = 'Stop'
\$child = ${windowsElevatedLaunch('-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand $encoded')} -PassThru
\$child.Id
''';
    final ProcessResult result = await Process.run('powershell.exe', <String>[
      '-NoProfile',
      '-NonInteractive',
      '-WindowStyle',
      'Hidden',
      '-EncodedCommand',
      windowsEncodedCommand(launch),
    ]);
    if (result.exitCode != 0) {
      throw StateError('Windows VPN permission was not granted.');
    }
    final int? supervisorPid = int.tryParse((result.stdout as String).trim());
    if (supervisorPid == null) {
      throw StateError('Windows did not start the VPN tunnel.');
    }
    return supervisorPid;
  }

  Future<bool> _nativeTunIsReady(Directory state) async {
    final String out = windowsSessionOutputs(state.path);
    final DateTime deadline = DateTime.now().add(const Duration(seconds: 50));
    while (DateTime.now().isBefore(deadline)) {
      final File failure = File('$out\\startup.error');
      if (await failure.exists()) {
        final String message = (await failure.readAsString()).trim();
        throw StateError(
          message.startsWith('Windows ')
              ? message
              : 'Windows could not configure the VPN tunnel.',
        );
      }
      if (await File('$out\\routes-ready').exists() &&
          await _tunAdapterIsUp()) {
        return true;
      }
      if (await File('$out\\stopped').exists()) {
        return false;
      }
      await Future<void>.delayed(const Duration(milliseconds: 250));
    }
    return false;
  }

  /// Whether every process this runtime started is still alive; null when
  /// it started none (nothing running, or a tunnel adopted from an earlier
  /// run whose processes this instance never learned).
  Future<bool?> engineRunning() async {
    final List<int> pids = <int>[?_xraySupervisorPid, ?_xrayPid, ?_hysteriaPid];
    if (pids.isEmpty) {
      return null;
    }
    for (final int pid in pids) {
      if (!await _processIsRunning(pid)) {
        return false;
      }
    }
    return true;
  }

  Future<bool> _processIsRunning(int pid) async {
    final ProcessResult result = await Process.run('tasklist.exe', <String>[
      '/FI',
      'PID eq $pid',
      '/NH',
    ]);
    return (result.stdout as String).contains('$pid');
  }

  /// Starts one of the bundled engines with no window and no pipes back to
  /// this app, and returns its process id.
  ///
  /// It used to go through a PowerShell script that could never have worked:
  /// its `$Error` parameter is PowerShell's own read-only variable, so the
  /// script failed before starting anything, and local proxy mode on Windows
  /// never ran. Once that was fixed the call hung instead -- the engine
  /// inherited PowerShell's output pipe and kept it open for as long as it
  /// ran. Detached, Windows gives the engine no console and nothing to
  /// inherit, and Dart quotes each argument itself.
  Future<int> _startHidden(String executable, List<String> arguments) async {
    final Process process = await Process.start(
      executable,
      arguments,
      workingDirectory: File(executable).parent.path,
      mode: ProcessStartMode.detached,
    );
    return process.pid;
  }

  Future<bool> _stopElevated(int pid, String? statePath) async {
    if (statePath != null) {
      await File('$statePath\\stop').create();
      for (int attempt = 0; attempt < 16; attempt++) {
        final ProcessResult status = await Process.run('tasklist.exe', <String>[
          '/FI',
          'PID eq $pid',
          '/NH',
        ]);
        if (!(status.stdout as String).contains('$pid')) {
          return true;
        }
        await Future<void>.delayed(const Duration(milliseconds: 250));
      }
    }
    _logs.add('Windows tunnel supervisor did not stop cleanly.');
    return false;
  }

  Future<void> _stopHidden(int pid) async {
    await Process.run('taskkill.exe', <String>['/PID', '$pid', '/F']);
    for (int attempt = 0; attempt < 12; attempt++) {
      final ProcessResult status = await Process.run('tasklist.exe', <String>[
        '/FI',
        'PID eq $pid',
        '/NH',
      ]);
      if (!(status.stdout as String).contains('$pid')) {
        return;
      }
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
  }

  Future<bool> _tunAdapterIsUp() => WindowsNetworkMonitor.isAdapterUp();
}
