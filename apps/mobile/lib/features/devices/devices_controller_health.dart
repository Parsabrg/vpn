part of 'devices_controller.dart';

/// Health checks: whether a tunnel reported up is still there, its engine
/// alive and its traffic moving, and ending one that is not.
mixin _HealthChecks on _DevicesCore {
  /// Keeps "Protected" honest for as long as it is on screen.
  ///
  /// The plugin reports CONNECTED once the core starts, and nothing after
  /// that: a tunnel torn down a moment later left the screen claiming
  /// protection over traffic that was going out directly. So Android is
  /// asked on an interval whether a VPN is still up.
  ///
  /// Two missing readings in a row, not one: the VPN network is registered
  /// a beat after the service starts, and a single early reading would call
  /// a healthy tunnel dead. A platform that cannot tell never trips it.
  @override
  void _watchTunnel() {
    _stopWatchingTunnel();
    _tunnelWatch = Timer.periodic(
      ref.read(tunnelWatchIntervalProvider),
      (_) => _checkTunnel(),
    );
    _accessWatch = Timer.periodic(
      ref.read(accessCheckIntervalProvider),
      (_) => unawaited(_checkAccess()),
    );
    _trafficWatch = Timer.periodic(
      ref.read(trafficCheckIntervalProvider),
      (_) => unawaited(_checkTraffic()),
    );
    // A route that is throttled rather than blocked lets the connect's own
    // request through and stalls seconds later (Cloudflare from Iran,
    // 2026-10-29): asked again soon, not a minute on.
    _checkTrafficSoon();
    _stopResumeWatch = ref.read(appResumedProvider)(() {
      unawaited(_checkTunnel());
      unawaited(_checkTrafficOnResume());
      unawaited(_checkAccess());
    });
  }

  @override
  void _stopWatchingTunnel() {
    _tunnelWatch?.cancel();
    _tunnelWatch = null;
    _tunnelMissingReadings = 0;
    _engineDeadReadings = 0;
    _accessWatch?.cancel();
    _accessWatch = null;
    _trafficWatch?.cancel();
    _trafficSoon?.cancel();
    _trafficSoon = null;
    _trafficWatch = null;
    _trafficFailedReadings = 0;
    _stopResumeWatch?.call();
    _stopResumeWatch = null;
  }

  /// Ends the connection and shows [reason], if there is one.
  ///
  /// [revokeOnServer] where the session still works: the server has taken
  /// the credential already or is about to, and saying so again is harmless.
  /// Without a session there is nobody to tell, so the tunnel is only
  /// stopped.
  @override
  Future<void> _endTunnel({
    required String? reason,
    required bool revokeOnServer,
  }) async {
    _stopWatchingTunnel();
    final String? deviceId = _connectedDeviceId ?? _storedDeviceId();
    if (revokeOnServer && deviceId != null) {
      await disconnect(deviceId);
    } else {
      await stopTunnelWithoutServer();
      await _forgetConnection();
    }
    if (!ref.mounted) {
      return;
    }
    // A revoke inside disconnect may well be refused; off all the same.
    state = state.copyWith(
      isSubmitting: false,
      peer: () => null,
      xrayClient: () => null,
      connectedServerCode: () => null,
      activeProtocolCode: () => null,
      activeProfileCode: () => null,
      tunnelEstablished: false,
      tunnelEstablishedAt: () => null,
      sanctionsOnly: false,
      localProxy: () => null,
      actionErrorMessage: () => reason,
    );
  }

  /// Disconnects properly before a sign-out, while the session can still
  /// tell the server. Leaving the tunnel up would keep a credential live for
  /// an account nobody is signed in to on this device.
  Future<void> disconnectBeforeSignOut() async {
    if (!state.isConnected && !state.tunnelEstablished) {
      return;
    }
    await _endTunnel(reason: null, revokeOnServer: true);
  }

  /// Stops the tunnel after the session ended without this device asking --
  /// revoked or expired. Nothing can be revoked any more; the server does
  /// its own removal.
  Future<void> endAfterSessionLost() async {
    if (!state.isConnected && !state.tunnelEstablished) {
      return;
    }
    await _endTunnel(reason: null, revokeOnServer: false);
  }

  /// Whether the engine behind a present interface still carries traffic.
  ///
  /// The interface check above cannot see this. A WireGuard session whose
  /// server stopped answering, or an xray/hysteria process that exited, leaves
  /// the VPN interface registered and every packet going nowhere -- and the
  /// screen said Protected over it. Two dead readings in a row take the
  /// tunnel down to Off with the reason, then try once to bring it back.
  Future<void> _checkEngine() async {
    final EngineHealth health;
    try {
      if (state.peer != null) {
        health = wireguardHealth(
          await _tunnel.latestHandshake(),
          DateTime.now(),
        );
      } else if (state.xrayClient != null) {
        health = engineProcessHealth(await _xrayTunnel.engineRunning());
      } else {
        return;
      }
    } catch (_) {
      return;
    }
    if (!ref.mounted || _tunnelWatch == null) {
      return;
    }
    if (health != EngineHealth.dead) {
      _engineDeadReadings = 0;
      return;
    }
    _engineDeadReadings++;
    if (_engineDeadReadings < 2 ||
        state.isSubmitting ||
        !state.tunnelEstablished) {
      return;
    }
    await _endDeadTunnel();
  }

  /// Whether an Xray or Hysteria2 tunnel still carries a request.
  ///
  /// The process check in [_checkEngine] cannot see this: the engine runs on
  /// when its server is blocked partway through a session, and nothing it
  /// logs says so. WireGuard has its handshake for this; here one small
  /// request is sent each interval, the one a connect is checked with. Three
  /// in a row unanswered -- about as long as WireGuard is given -- and the
  /// tunnel is taken down and tried again once, where the connect says which
  /// it was: offline, the server gone, or the protocol blocked.
  Future<void> _checkTraffic({bool data = false}) async {
    // A local proxy carries only what is sent to it.
    if (_checkingTraffic ||
        state.xrayClient == null ||
        state.localProxy != null ||
        state.isSubmitting ||
        !state.tunnelEstablished ||
        !ref.read(trafficCheckMeaningfulProvider)()) {
      return;
    }
    _checkingTraffic = true;
    try {
      final bool carries = await _tunnelAnswers(data: data);
      if (!ref.mounted || _trafficWatch == null) {
        return;
      }
      if (carries) {
        _trafficFailedReadings = 0;
        return;
      }
      _trafficFailedReadings++;
      if (_trafficFailedReadings < 3 ||
          state.isSubmitting ||
          !state.tunnelEstablished) {
        // Confirmed or cleared within seconds: three one-a-minute readings
        // kept a stalled tunnel reading "Protected" for three minutes.
        if (_trafficFailedReadings < 3) {
          _checkTrafficSoon();
        }
        return;
      }
      await _endDeadTunnel();
    } finally {
      _checkingTraffic = false;
    }
  }

  void _checkTrafficSoon() {
    _trafficSoon?.cancel();
    _trafficSoon = Timer(
      ref.read(trafficRecheckDelayProvider),
      () => unawaited(_checkTraffic(data: true)),
    );
  }

  /// One reading of the traffic watch: a request through the tunnel, and a
  /// DNS question over its UDP side -- the way every app's DNS goes, and
  /// which the request alone never touches (the proxy looks its name up
  /// itself, over TCP).
  Future<bool> _tunnelAnswers({bool data = false}) async {
    // The soon readings also move real data: a throttled route answers one
    // small request and stalls a transfer, and read "Protected" for minutes
    // with 170 KB moved (Windows, 2026-10-30). Not every minute: that would
    // be 180 MB a day on a phone's data plan.
    if (data &&
        (!await ref.read(tunnelMovesDataProvider)(_tunnelProxy) ||
            !ref.mounted)) {
      return false;
    }
    final LocalProxy? proxy = _tunnelProxy;
    if (!await ref.read(tunnelCarriesTrafficProvider)(proxy) || !ref.mounted) {
      return false;
    }
    final InternetAddress? resolver = _tunnelResolver();
    return proxy == null ||
        resolver == null ||
        await ref.read(tunnelResolvesProvider)(proxy, resolver);
  }

  /// Where this app's own measurements -- the diagnostics -- must go to
  /// cross the tunnel, or null where they already do.
  ///
  /// On Android this app is outside its own Xray/Hysteria2 VPN, so a request
  /// from it measures the bare line: the speed and packet-loss tests said
  /// "through the VPN" over the ISP's figures, and the leak test reported
  /// the real address and the ISP's forged DNS as leaks. They go through the
  /// tunnel's local proxy instead -- or, in local proxy mode, through that,
  /// which is what a proxied app gets. WireGuard and the desktop carry the
  /// app's own traffic, so nothing is needed there.
  ({LocalProxy proxy, InternetAddress? resolver})? get measurementRoute {
    if (!state.tunnelEstablished) {
      return null;
    }
    final LocalProxy? proxy =
        state.localProxy ??
        (defaultTargetPlatform == TargetPlatform.android &&
                state.xrayClient != null
            ? _tunnelProxy
            : null);
    return proxy == null ? null : (proxy: proxy, resolver: _tunnelResolver());
  }

  /// The first IPv4 resolver the tunnel hands Android, or null.
  InternetAddress? _tunnelResolver() {
    final XrayClientResult? client = state.xrayClient;
    if (client == null) {
      return null;
    }
    final Object? servers = dnsModuleFor(
      client,
      ref.read(advancedSettingsControllerProvider),
    )['servers'];
    for (final Object? server
        in servers is List ? servers : const <Object?>[]) {
      final InternetAddress? address = server is String
          ? InternetAddress.tryParse(server)
          : null;
      if (address?.type == InternetAddressType.IPv4) {
        return address;
      }
    }
    return null;
  }

  /// Checks the tunnel the moment the app is opened again.
  ///
  /// Off screen on Android, [_checkTraffic] asks nothing (see
  /// trafficCheckMeaningfulProvider), so a tunnel that died meanwhile still
  /// read "Connected" when the app was opened -- and went on reading it
  /// through three more one-a-minute checks. Here it is asked at once, three
  /// times a couple of seconds apart, and taken down and tried again if none
  /// of them is answered.
  Future<void> _checkTrafficOnResume() async {
    bool unchanged() =>
        ref.mounted &&
        _trafficWatch != null &&
        !state.isSubmitting &&
        state.tunnelEstablished;
    if (_checkingTraffic ||
        state.xrayClient == null ||
        state.localProxy != null ||
        !unchanged()) {
      return;
    }
    _checkingTraffic = true;
    try {
      for (int tried = 0; tried < 3; tried++) {
        if (tried > 0) {
          await Future<void>.delayed(const Duration(seconds: 2));
        }
        if (!unchanged()) {
          return;
        }
        if (await _tunnelAnswers()) {
          _trafficFailedReadings = 0;
          return;
        }
      }
      if (unchanged()) {
        await _endDeadTunnel();
      }
    } finally {
      _checkingTraffic = false;
    }
  }

  /// Takes down a tunnel that carries nothing, and tries once to bring it
  /// back.
  Future<void> _endDeadTunnel() async {
    final String? deviceId = _connectedDeviceId ?? _storedDeviceId();
    final String? deadServer = state.connectedServerCode;
    final String? deadProfile = state.activeProfileCode;
    if (deadServer != null && deadProfile != null) {
      await _recordProtocol(deadServer, deadProfile, ProtocolOutcome.drop);
    }
    final DateTime now = DateTime.now();
    final DateTime? last = _lastEngineRecovery;
    final bool retry =
        deviceId != null &&
        (last == null || now.difference(last) >= _engineRecoveryInterval);
    // Off, never "Protected": nothing is being carried. The server-side
    // credential is kept, so a reconnect reuses it. "Reconnecting" only when
    // one follows: once per interval, and the second stall said it anyway.
    final AppText text = ref.read(appTextProvider);
    await _endTunnel(
      reason: retry ? text.errorTunnelStopped : text.errorTunnelNoTraffic,
      revokeOnServer: false,
    );
    if (!ref.mounted || !retry) {
      return;
    }
    _lastEngineRecovery = now;
    // Dead after carrying traffic is how a throttled address looks; the
    // next route's tunnel may not be. See moveApiRouteProvider.
    ref.read(moveApiRouteProvider)();
    await connect(deviceId);
  }

  Future<void> _checkTunnel() async {
    if (!state.tunnelEstablished) {
      _stopWatchingTunnel();
      return;
    }
    // Two calls into Android every two seconds, all night, mostly keep the
    // screen right. Out of sight, every thirty: a dead engine is still taken
    // down and tried again within a minute (two readings) while the person
    // uses other apps, and the app's return checks at once (_watchTunnel).
    if (!ref.read(trafficCheckMeaningfulProvider)()) {
      final DateTime now = DateTime.now();
      if (now.difference(_lastTunnelCheckAway) <
          backgroundTunnelCheckInterval) {
        return;
      }
      _lastTunnelCheckAway = now;
    }
    bool? up;
    try {
      // Another app's VPN counts as this tunnel gone: taking consent is how
      // another VPN app replaces it.
      final LocalProxy? proxy = state.localProxy;
      up = proxy != null
          ? await ref.read(loopbackPortProbeProvider)(proxy.port)
          : switch (await _tunnel.activeVpn()) {
              VpnOwner.own => true,
              VpnOwner.none || VpnOwner.other => false,
              null => null,
            };
    } catch (_) {
      up = null;
    }
    if (!ref.mounted || _tunnelWatch == null) {
      return;
    }
    if (up != false) {
      _tunnelMissingReadings = 0;
      if (up == true) {
        await _checkEngine();
      }
      return;
    }
    _tunnelMissingReadings++;
    // A disconnect in progress takes the tunnel down on purpose.
    if (_tunnelMissingReadings < 2 ||
        state.isSubmitting ||
        !state.tunnelEstablished) {
      return;
    }
    _stopWatchingTunnel();
    unawaited(_forgetConnection());
    // Gone without this app taking it down: another VPN app connected, or it
    // was disconnected from Android's settings. That is the end of the
    // connection, not a fault to retry -- somebody chose a different VPN --
    // so it is taken down the rest of the way and the screen says Off. It used to stop at "Not protected" with the
    // client still registered, which read as Nebula still being on.
    state = state.copyWith(
      tunnelEstablished: false,
      tunnelEstablishedAt: () => null,
      sanctionsOnly: false,
      localProxy: () => null,
    );
    final String? deviceId = _connectedDeviceId ?? _storedDeviceId();
    if (deviceId != null) {
      // The local tunnel is already gone, so this only revokes and clears.
      await disconnect(deviceId);
    }
    if (ref.mounted && state.isConnected) {
      // The revoke did not go through -- offline, most likely. Off all the
      // same: nothing is tunnelling, and the client is revoked the next time
      // this device connects or the server prunes it.
      state = state.copyWith(
        isSubmitting: false,
        peer: () => null,
        xrayClient: () => null,
        connectedServerCode: () => null,
        activeProtocolCode: () => null,
        activeProfileCode: () => null,
        actionErrorMessage: () => null,
      );
    }
  }

  @override
  String? _storedDeviceId() {
    try {
      return ref.read(deviceIdStoreProvider).read();
    } catch (_) {
      return null;
    }
  }

  /// Whether a WireGuard tunnel just brought up has heard from its server.
  ///
  /// Waits through three of WireGuard's handshake attempts, which are five
  /// seconds apart. A platform that cannot tell is taken at its word that
  /// the tunnel is up, as it always was.
  @override
  Future<bool> _serverAnswered(int attempt) async {
    final Duration step = ref.read(tunnelSettleStepProvider);
    for (int waited = 0; waited < _handshakeWaitSteps; waited++) {
      // The longest wait in a connect, and so the likeliest place for Cancel.
      if (!ref.mounted || _cancelled(attempt)) {
        return false;
      }
      if (await _tunnel.hasHandshake() != false) {
        return true;
      }
      await Future<void>.delayed(step);
    }
    return false;
  }

  /// Whether a request gets out through a tunnel just brought up.
  ///
  /// Three tries, each with its own deadline: the first request over a new
  /// tunnel can be slow, through a CDN especially.
  @override
  Future<bool> _tunnelCarriesTraffic(
    int attempt, {
    bool viaProxy = true,
  }) async {
    final Future<bool> Function(LocalProxy?) carries = ref.read(
      tunnelCarriesTrafficProvider,
    );
    Future<bool> probe() => carries(viaProxy ? _tunnelProxy : null);
    for (int tried = 0; tried < 3; tried++) {
      if (!ref.mounted || _cancelled(attempt)) {
        return false;
      }
      final Stopwatch took = Stopwatch()..start();
      final bool answered = await probe();
      if (!answered && took.elapsed >= _probeGaveUp) {
        // It waited out its whole deadline: nothing is there. Trying twice
        // more only adds the same wait again (a dead server sat at
        // Connecting for 79 s). A quick failure -- the engine still coming
        // up -- is still tried again.
        return false;
      }
      if (answered) {
        // And once more: a throttled address carries the first request and
        // stalls everything after it (measured from Iran, 2026-10-06), so
        // one answer does not say the tunnel stays up. And quickly: raw
        // TCP+TLS to a throttled address answered this in 4.8-7.2 s while a
        // 5 MB download got nothing, where working tunnels took 0.6-2.2 s
        // (on the phone, 2026-10-17) -- "Protected" over a tunnel that slow
        // is the screen saying connected while nothing loads.
        return await probe().timeout(_confirmWithin, onTimeout: () => false);
      }
    }
    return false;
  }

  @override
  Future<String> _probeConfig(
    XrayClientResult credential,
    AdvancedSettings settings,
  ) async {
    await ref.read(echServerRefreshProvider)(echConfigListFor(credential));
    return credential.transport == 'hysteria'
        ? renderHysteriaDelayProbeConfigJson(
            credential,
            localProxy: await LocalProxy.generate(),
          )
        : renderXrayDelayProbeConfigJson(credential, settings: settings);
  }
}
