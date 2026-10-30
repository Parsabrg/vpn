part of 'devices_controller.dart';

/// The protocol test: latency for every protocol, then download speed.
mixin _SpeedTests on _DevicesCore {
  /// Tests every profile of the selected server with a real request through
  /// it, like v2ray's "real delay", and records each result as it lands.
  ///
  /// A port check is not enough and was the reason for this: gRPC routed
  /// through nginx answered a TCP connect and carried nothing. Each Xray
  /// profile is dialled exactly as Connect would dial it. Hysteria2 is
  /// measured through the reference client, started for the test, because
  /// Xray drops its obfuscation; WireGuard through Xray's own WireGuard
  /// client, with this device's key.
  ///
  /// Tests the credentials already on this phone, as v2ray tests the
  /// configs it holds, and asks the server only for a profile it has never
  /// been given one for. Those requests go one at a time -- the server
  /// handles a device's requests in turn, so sent together the later ones
  /// time out and read as unreachable -- while the measurements run all at
  /// once: one after another, every unreachable profile cost its full
  /// timeout in turn and a server took over a minute. A credential requested
  /// here is kept and saved, as a connect would.
  ///
  /// ponytail: a saved credential revoked since reads as unreachable until
  /// the next connect replaces it. Re-request on a failed saved credential if
  /// that ever misleads anyone.
  ///
  /// [server] is the one the picker is showing, which need not be the
  /// selected one yet: with only the selection, a first-time user -- who has
  /// not pressed "Use" -- pressed Test and nothing happened. Seen on
  /// Windows.
  Future<void> pingProtocols(String deviceId, {AvailableServer? server}) async {
    server ??= state.selectedServer;
    if (server == null || state.pinging) {
      return;
    }
    state = state.copyWith(
      pinging: true,
      protocolDelaysServer: () => server!.code,
      protocolDelays: <String, ProtocolDelay>{
        for (final AvailableProfile profile in server.profiles)
          profile.code: const ProtocolDelay.testing(),
      },
    );
    // The list as the server gives it now. Read only at launch, a route the
    // server has changed since -- WebSocket moved onto Cloudflare -- was
    // tested where it no longer is, and read -1 until the app restarted.
    final String code = server.code;
    AvailableServer? fresh;
    try {
      final List<AvailableServer> servers = await _repository
          .listAvailableServers();
      if (!ref.mounted) {
        return;
      }
      state = state.copyWith(servers: servers);
      fresh = servers.where((AvailableServer s) => s.code == code).firstOrNull;
    } catch (_) {
      // Offline or the server unreachable: test what is already listed.
    }
    final AvailableServer tested = fresh ?? server;
    final AdvancedSettings settings = ref.read(
      advancedSettingsControllerProvider,
    );
    void record(AvailableProfile profile, ProtocolDelay delay) {
      if (!ref.mounted) {
        return;
      }
      state = state.copyWith(
        protocolDelays: <String, ProtocolDelay>{
          ...state.protocolDelays,
          profile.code: delay,
        },
      );
    }

    final List<Future<void>> measuring = <Future<void>>[];
    final List<AvailableProfile> wireguard = <AvailableProfile>[];
    final Map<AvailableProfile, XrayClientResult> answered =
        <AvailableProfile, XrayClientResult>{};
    // A few at a time: a subscription's group can hold a hundred links, and
    // each test starts an engine of its own on the phone.
    int running = 0;
    final List<Completer<void>> waiting = <Completer<void>>[];
    Future<void> slot() async {
      while (running >= 16) {
        final Completer<void> turn = Completer<void>();
        waiting.add(turn);
        await turn.future;
      }
      running++;
    }

    void release() {
      running--;
      if (waiting.isNotEmpty) {
        waiting.removeAt(0).complete();
      }
    }

    for (final AvailableProfile profile in tested.profiles) {
      if (profile.protocolCode == wireguardProtocolCode) {
        wireguard.add(profile);
        continue;
      }
      final XrayClientResult? credential = await _testCredential(
        deviceId: deviceId,
        serverCode: tested.code,
        profileCode: profile.code,
        listedPort: profile.requiredPort,
      );
      if (!ref.mounted) {
        return;
      }
      if (credential == null) {
        record(profile, const ProtocolDelay.failed());
        continue;
      }
      measuring.add(() async {
        await slot();
        try {
          await _measureOne(
            deviceId,
            tested,
            profile,
            credential,
            settings,
            record,
            answered,
          );
        } finally {
          release();
        }
      }());
    }
    if (wireguard.isNotEmpty) {
      measuring.add(
        _pingWireGuard(
          deviceId: deviceId,
          serverCode: tested.code,
          profiles: wireguard,
          record: record,
        ),
      );
    }
    await Future.wait(measuring);
    // Then the download, one protocol at a time so they do not share the
    // line, as v2rayN's latency-and-speed test: a throttled route answers
    // the delay test and stalls a transfer (Windows, 2026-10-30).
    for (final MapEntry<AvailableProfile, XrayClientResult> entry
        in answered.entries) {
      if (!ref.mounted) {
        return;
      }
      final double? megabits;
      try {
        megabits = await _xrayTunnel.measureDownload(
          await _probeConfig(entry.value, settings),
          url: _speedProbeUrl,
        );
      } catch (_) {
        continue;
      }
      if (megabits == null) {
        continue;
      }
      final int? ms = state.protocolDelays[entry.key.code]?.milliseconds;
      if (ms != null) {
        record(entry.key, ProtocolDelay.measured(ms, megabits: megabits));
      }
    }
    if (!ref.mounted) {
      return;
    }
    state = state.copyWith(pinging: false);
  }

  Future<void> _measureOne(
    String deviceId,
    AvailableServer tested,
    AvailableProfile profile,
    XrayClientResult credential,
    AdvancedSettings settings,
    void Function(AvailableProfile, ProtocolDelay) record,
    Map<AvailableProfile, XrayClientResult> answered,
  ) async {
    XrayClientResult used = credential;
    ProtocolDelay delay = await _measureXray(credential, settings);
    // Not for a link of the device's own: asked again it is the same link.
    if (delay.outcome == DelayOutcome.failed && !isOwnLinkCode(tested.code)) {
      // Once more, as the server gives the credential now. A saved one
      // can name an address the server has since given up: after its
      // IPv4 was swapped (2026-10-07), Hysteria2 -- dialled by address --
      // tested -1 while connecting, which asks afresh, worked. And UDP
      // comes and goes on Iranian networks: Hysteria2 and WireGuard
      // tested -1 and a minute later measured, while TCP never failed.
      final XrayClientResult? fresh = await _freshTestCredential(
        deviceId: deviceId,
        serverCode: tested.code,
        profileCode: profile.code,
      );
      used = fresh ?? credential;
      delay = await _measureXray(used, settings);
    }
    if (delay.outcome == DelayOutcome.measured) {
      answered[profile] = used;
    }
    record(profile, delay);
  }

  /// The credential a test uses: the one in use, else the saved one, else a
  /// fresh one from the server, which is then saved. Null when there is
  /// none -- including when the server cannot be reached, in which case
  /// nothing reached through it works either.
  Future<XrayClientResult?> _testCredential({
    required String deviceId,
    required String serverCode,
    required String profileCode,
    int? listedPort,
  }) async {
    if (state.tunnelEstablished &&
        state.connectedServerCode == serverCode &&
        state.activeProfileCode == profileCode &&
        state.xrayClient != null) {
      return state.xrayClient;
    }
    // A link of the device's own is its own credential: nothing is issued,
    // so nothing is saved -- a copy saved before a fix to how links are read
    // went on being tested -- and secure storage is not touched a hundred
    // times for a subscription's group.
    if (isOwnLinkCode(serverCode)) {
      try {
        return await _repository.requestXrayClient(
          deviceId: deviceId,
          serverCode: serverCode,
          protocolProfileCode: profileCode,
        );
      } catch (_) {
        return null;
      }
    }
    final XrayCredentialStore store = ref.read(xrayCredentialStoreProvider);
    final XrayClientResult? saved = await _recalled(
      store,
      serverCode: serverCode,
      profileCode: profileCode,
    );
    // Only while it still points where the server now lists the protocol: a
    // credential issued on another route (the direct address, before the
    // route moved onto Cloudflare) would test a path the app no longer uses.
    if (saved != null && (listedPort == null || saved.port == listedPort)) {
      return saved;
    }
    return _freshTestCredential(
      deviceId: deviceId,
      serverCode: serverCode,
      profileCode: profileCode,
    );
  }

  /// A credential straight from the server, saved for next time; null when
  /// the server cannot be reached.
  Future<XrayClientResult?> _freshTestCredential({
    required String deviceId,
    required String serverCode,
    required String profileCode,
  }) async {
    final XrayCredentialStore store = ref.read(xrayCredentialStoreProvider);
    try {
      final XrayClientResult credential = await _repository.requestXrayClient(
        deviceId: deviceId,
        serverCode: serverCode,
        protocolProfileCode: profileCode,
      );
      await _remember(
        store,
        serverCode: serverCode,
        profileCode: profileCode,
        credential: credential,
      );
      return credential;
    } catch (_) {
      return null;
    }
  }

  Future<ProtocolDelay> _measureXray(
    XrayClientResult credential,
    AdvancedSettings settings,
  ) async {
    try {
      return _measure(await _probeConfig(credential, settings));
    } catch (_) {
      return const ProtocolDelay.failed();
    }
  }

  /// The device has one WireGuard peer per server, which the server hands to
  /// whichever profile asks -- so one peer and one measurement answer for
  /// every WireGuard profile. Asking again per profile was refused while the
  /// first was still being applied, and read as unreachable. The peer is
  /// revoked again afterwards, as Disconnect revokes one, unless this device
  /// is connected on it.
  Future<void> _pingWireGuard({
    required String deviceId,
    required String serverCode,
    required List<AvailableProfile> profiles,
    required void Function(AvailableProfile, ProtocolDelay) record,
  }) async {
    final bool connected =
        state.tunnelEstablished &&
        state.connectedServerCode == serverCode &&
        state.peer != null;
    ProtocolDelay delay = const ProtocolDelay.failed();
    try {
      final WireGuardKeyPair keyPair = await _currentOrNewKeyPair();
      final WireGuardPeerResult peer = connected
          ? state.peer!
          : await _repository.requestPeer(
              deviceId: deviceId,
              serverCode: serverCode,
              protocolProfileCode: profiles.first.code,
              publicKey: keyPair.publicKeyBase64,
            );
      delay = await _measure(
        renderWireGuardDelayProbeConfigJson(
          privateKeyBase64: keyPair.privateKeyBase64,
          peer: peer,
        ),
      );
      if (!connected) {
        await _repository.revokePeer(
          deviceId: deviceId,
          serverCode: serverCode,
        );
      }
    } catch (_) {
      // No peer is a failed test; a revoke that did not go through is left
      // for the server's own cleanup, not a reason to change the answer.
    }
    for (final AvailableProfile profile in profiles) {
      record(profile, delay);
    }
  }

  Future<ProtocolDelay> _measure(String config) async {
    try {
      return _delayFrom(
        await _xrayTunnel.measureDelay(config, url: _delayProbeUrl),
      );
    } catch (_) {
      return const ProtocolDelay.failed();
    }
  }
}
