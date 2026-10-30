part of 'devices_controller.dart';

/// Connecting and disconnecting: the automatic order, WireGuard and Xray
/// connects, cancel, and clearing up a tunnel left from before.
mixin _Connecting on _DevicesCore {
  @override
  Future<void> connect(String deviceId) async {
    _connectedDeviceId = deviceId;
    final String? serverCode = state.selectedServerCode;
    final String? profileCode = state.selectedProfileCode;
    if (serverCode == null || profileCode == null) {
      return;
    }
    if (state.selectedServer?.maintenance ?? false) {
      // Said before anything is registered or started: the server would
      // refuse, and this says why.
      state = state.copyWith(
        actionErrorMessage: () =>
            ref.read(appTextProvider).errorServerMaintenance,
      );
      return;
    }

    final int attempt = ++_attemptCounter;
    _liveAttempt = attempt;
    final Future<void>? previous = _attemptRun;
    final Completer<void> run = Completer<void>();
    _attemptRun = run.future;
    try {
      if (previous != null) {
        // A cancelled attempt can still be undoing what it started. Its
        // teardown landing after this one's tunnel came up would take the
        // new connection down with it, so this one waits its turn.
        state = state.copyWith(
          isSubmitting: true,
          actionErrorMessage: () => null,
        );
        await previous;
        if (!ref.mounted || _cancelled(attempt)) {
          return;
        }
        state = state.copyWith(isSubmitting: false);
      }

      if (profileCode == automaticProfileCode) {
        await _connectAutomatically(
          attempt: attempt,
          deviceId: deviceId,
          serverCode: serverCode,
        );
      } else {
        await _connectProfile(
          attempt: attempt,
          deviceId: deviceId,
          serverCode: serverCode,
          profileCode: profileCode,
        );
      }
    } finally {
      if (_liveAttempt == attempt) {
        _liveAttempt = 0;
      }
      run.complete();
      if (identical(_attemptRun, run.future)) {
        _attemptRun = null;
      }
    }
  }

  Future<void> _connectProfile({
    required int attempt,
    required String deviceId,
    required String serverCode,
    required String profileCode,
  }) async {
    if (_protocolCodeFor(profileCode) != wireguardProtocolCode) {
      await _connectXray(
        attempt: attempt,
        deviceId: deviceId,
        serverCode: serverCode,
        protocolProfileCode: profileCode,
      );
    } else {
      await _connectWireGuard(
        attempt: attempt,
        deviceId: deviceId,
        serverCode: serverCode,
        protocolProfileCode: profileCode,
      );
    }
    if (!ref.mounted || _cancelled(attempt)) {
      return;
    }
    if (state.tunnelEstablished) {
      await _recordProtocol(serverCode, profileCode, ProtocolOutcome.success);
    } else if (_aboutTheProtocol(state.actionErrorMessage)) {
      await _recordProtocol(serverCode, profileCode, ProtocolOutcome.failure);
    }
  }

  /// Whether a failed connect says something about the protocol, rather than
  /// the account, the server as a whole, or this device being offline --
  /// none of which another protocol would change, so none count against it.
  bool _aboutTheProtocol(String? error) {
    final AppText text = ref.read(appTextProvider);
    return error == text.errorTunnelNoTraffic ||
        error == text.errorWireguardNoHandshake ||
        error == text.errorServerCertificate;
  }

  @override
  Future<void> _recordProtocol(
    String serverCode,
    String profileCode,
    ProtocolOutcome outcome,
  ) async {
    try {
      await ref
          .read(protocolHistoryStoreProvider)
          .record(serverCode, profileCode, outcome);
    } catch (_) {
      // A record that could not be kept only costs ordering later.
    }
  }

  /// Automatic: one protocol after another until one carries traffic.
  ///
  /// First the one that last worked on this server, then the list's own
  /// order -- the last test's fastest first, no answer last, gRPC after the
  /// rest. Each try is a whole connect, whose own checks say whether traffic
  /// got through and undo it if not, so a failed try leaves nothing behind.
  /// Stops at once for what no other protocol would change: an allowance
  /// used up, or the server asking the device to slow down.
  Future<void> _connectAutomatically({
    required int attempt,
    required String deviceId,
    required String serverCode,
  }) async {
    final AvailableServer? server = state.servers
        .where((AvailableServer s) => s.code == serverCode)
        .firstOrNull;
    if (server == null || server.profiles.isEmpty) {
      return;
    }
    // Hand-picked only (see AvailableProfile.manualOnly), unless a server
    // offers nothing else.
    final List<AvailableProfile> candidates =
        server.profiles.any((AvailableProfile p) => !p.manualOnly)
        ? server.profiles
              .where((AvailableProfile p) => !p.manualOnly)
              .toList(growable: false)
        : server.profiles;
    String? lastWorked;
    try {
      final ConnectionRecord? record = await _records.read();
      if (record?.serverCode == serverCode) {
        lastWorked = record!.profileCode;
      }
    } catch (_) {
      // No history is the same as none.
    }
    Map<String, ProtocolHistory> history = <String, ProtocolHistory>{};
    try {
      history = ref.read(protocolHistoryStoreProvider).forServer(serverCode);
    } catch (_) {
      // No history is the same as none.
    }
    // Best quality first (roadmap section 9): this device's own record of
    // each protocol here, and the last test. The last one that worked leads
    // the input, so it wins a tie -- and with no record yet, the order is
    // the one Automatic always used.
    final Set<String> inbounds = <String>{};
    final List<AvailableProfile> order =
        rankByQuality(
              <AvailableProfile>[
                ...candidates.where(
                  (AvailableProfile p) => p.code == lastWorked,
                ),
                ...orderedProfiles(
                  candidates,
                  state.delaysFor(server.code),
                  pinging: false,
                ).where((AvailableProfile p) => p.code != lastWorked),
              ],
              history,
              state.delaysFor(server.code),
              DateTime.now().toUtc(),
            )
            // A protocol and its ad-block twin are one inbound on the server: if
            // one carries nothing so does the other. Trying both spent half of
            // Automatic's tries on Cloudflare routes that were stalled, and the
            // one protocol that worked was never reached (Windows, 2026-10-29).
            .where((AvailableProfile p) => inbounds.add(_inboundOf(p.code)))
            .take(_automaticTries)
            .toList();

    final AppText text = ref.read(appTextProvider);
    for (final AvailableProfile profile in order) {
      if (!ref.mounted || _cancelled(attempt)) {
        return;
      }
      state = state.copyWith(actionErrorMessage: () => null);
      await _connectProfile(
        attempt: attempt,
        deviceId: deviceId,
        serverCode: serverCode,
        profileCode: profile.code,
      );
      if (!ref.mounted || _cancelled(attempt) || state.tunnelEstablished) {
        return;
      }
      final String? error = state.actionErrorMessage;
      // A refused VPN permission is the person's answer, not the network's:
      // the next protocol would ask again, and the closing "none of the
      // protocols got through" would hide why (found on a first install,
      // 2026-10-17).
      if (error == text.errorQuotaExhausted ||
          error == text.errorRateLimited ||
          error == text.errorOffline ||
          error == text.vpnPermissionNotGranted ||
          error ==
              text.errorProxyPortInUse(
                '${ref.read(advancedSettingsControllerProvider).localProxyPort}',
              )) {
        return;
      }
    }
    if (ref.mounted && !_cancelled(attempt)) {
      state = state.copyWith(
        isSubmitting: false,
        actionErrorMessage: () => text.errorNoProtocolWorked,
      );
    }
  }

  /// Whether Cancel can do anything: a connect is in flight and has not been
  /// cancelled already. The Connecting screen also covers a disconnect, which
  /// is not something to cancel.
  bool get canCancelConnect => _liveAttempt != 0;

  /// Cancel on the Connecting screen.
  ///
  /// The screen goes back to Off at once. The attempt cannot be stopped
  /// mid-step -- a request already sent will be answered, a tunnel already
  /// starting will start -- so it stands down at its next step and undoes
  /// what it got as far as. Waiting for that instead would keep somebody who
  /// pressed Cancel looking at Connecting for as long as a slow network takes
  /// to answer, which is exactly when they press it.
  void cancelConnect() {
    if (_liveAttempt == 0) {
      return;
    }
    _liveAttempt = 0;
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
      actionErrorMessage: () => null,
    );
  }

  @override
  bool _cancelled(int attempt) => attempt != _liveAttempt;

  /// Undoes what a cancelled connect got as far as: the tunnel, if it had
  /// started, and the credential, if the server had issued one -- so nothing
  /// is left live on a server for a connection nobody wanted.
  ///
  /// Never touches the screen. Cancel already put it back to Off, and a
  /// connect started since may own it by now.
  Future<void> _undoCancelledConnect({
    required String deviceId,
    required String serverCode,
    required String profileCode,
    required bool xray,
    required bool tunnelStarted,
  }) async {
    if (tunnelStarted) {
      try {
        if (xray) {
          await _xrayTunnel.disconnect();
        } else {
          await _tunnel.disconnect();
        }
        // The same settle as a disconnect: the revoke below would otherwise
        // race Android switching the default route back.
        await Future<void>.delayed(const Duration(milliseconds: 600));
      } catch (_) {
        // Revoke regardless.
      }
    }
    if (!ref.mounted) {
      return;
    }
    try {
      if (xray) {
        await _revokeXrayClient(
          deviceId: deviceId,
          serverCode: serverCode,
          protocolProfileCode: profileCode,
        );
      } else {
        await _repository.revokePeer(
          deviceId: deviceId,
          serverCode: serverCode,
        );
      }
    } catch (_) {
      // The server prunes a credential nobody connects with.
    }
  }

  Future<void> _connectWireGuard({
    required int attempt,
    required String deviceId,
    required String serverCode,
    required String protocolProfileCode,
  }) async {
    // WireGuard is a VPN protocol with no proxy to run as. Connecting it as
    // a VPN anyway would quietly do the opposite of the switch.
    if (ref.read(advancedSettingsControllerProvider).connectionMode ==
        ConnectionMode.localProxy) {
      state = state.copyWith(
        actionErrorMessage: () =>
            ref.read(appTextProvider).errorWireguardNotProxy,
      );
      return;
    }
    state = state.copyWith(isSubmitting: true, actionErrorMessage: () => null);
    try {
      final WireGuardKeyPair keyPair = await _currentOrNewKeyPair();
      final WireGuardPeerResult result = await runGuarded(
        ref,
        () => _repository.requestPeer(
          deviceId: deviceId,
          serverCode: serverCode,
          protocolProfileCode: protocolProfileCode,
          publicKey: keyPair.publicKeyBase64,
        ),
      );
      if (!ref.mounted) {
        return;
      }
      if (_cancelled(attempt)) {
        await _undoCancelledConnect(
          deviceId: deviceId,
          serverCode: serverCode,
          profileCode: protocolProfileCode,
          xray: false,
          tunnelStarted: false,
        );
        return;
      }
      // The server-side peer is provisioned regardless of what happens
      // next -- record it even if bringing up the local tunnel fails, so
      // the user isn't shown "not connected" when the server actually did
      // accept them.
      state = state.copyWith(
        peer: () => result,
        connectedServerCode: () => serverCode,
        activeProtocolCode: () => wireguardProtocolCode,
        activeProfileCode: () => protocolProfileCode,
      );

      bool tunnelUp = false;
      String? tunnelError;
      try {
        await _stopLeftoverTunnel();
        final bool granted = await _tunnel.requestPermission();
        if (!granted) {
          tunnelError = ref.read(appTextProvider).vpnPermissionNotGranted;
        } else {
          await _tunnel.connect(
            renderWireGuardConfig(
              privateKeyBase64: keyPair.privateKeyBase64,
              peer: result,
              bypassLocalNetwork: ref
                  .read(protectionControllerProvider)
                  .bypassLocalNetwork,
            ),
            excludedPackages: _excludedPackages,
            killSwitch: ref
                .read(protectionControllerProvider)
                .blockWhenVpnDrops,
          );
          tunnelUp = true;
        }
      } catch (error) {
        tunnelError = userFacingErrorMessage(error, ref.read(appTextProvider));
      }

      if (!ref.mounted) {
        return;
      }
      // A handshake alone is not traffic: on a network that lets the
      // server's packets in and drops the phone's, the phone answers the
      // server's handshakes and the tunnel still carries nothing ("Protected"
      // for minutes on the phone, 2026-10-17). This app's own requests go
      // through a WireGuard tunnel, so a plain one asks the question.
      if (!_cancelled(attempt) &&
          tunnelUp &&
          !(await _serverAnswered(attempt) &&
              await _tunnelCarriesTraffic(attempt, viaProxy: false)) &&
          !_cancelled(attempt)) {
        // The interface is up and the server never answered, so nothing
        // this device sends goes anywhere. Saying "Protected" over that is
        // the one thing this screen must not do: it looks connected, and
        // every app on the phone quietly stops working. Undo the connection,
        // server side included, and say why.
        if (!ref.mounted) {
          return;
        }
        state = state.copyWith(isSubmitting: false, tunnelEstablished: true);
        await disconnect(deviceId);
        if (ref.mounted) {
          state = state.copyWith(
            actionErrorMessage: () =>
                ref.read(appTextProvider).errorWireguardNoHandshake,
          );
        }
        return;
      }
      if (!ref.mounted) {
        return;
      }
      if (_cancelled(attempt)) {
        await _undoCancelledConnect(
          deviceId: deviceId,
          serverCode: serverCode,
          profileCode: protocolProfileCode,
          xray: false,
          tunnelStarted: tunnelUp,
        );
        return;
      }

      state = state.copyWith(
        isSubmitting: false,
        tunnelEstablished: tunnelUp,
        // Recorded only when this process saw the tunnel come up, so a
        // session it did not start reports no elapsed time rather than a
        // wrong one.
        tunnelEstablishedAt: () => tunnelUp ? DateTime.now() : null,
        actionErrorMessage: () => tunnelError,
      );
      if (tunnelUp) {
        _watchTunnel();
        await _recordConnection();
      }
    } catch (error) {
      if (!ref.mounted || _cancelled(attempt)) {
        return;
      }
      state = state.copyWith(
        isSubmitting: false,
        actionErrorMessage: () =>
            userFacingErrorMessage(error, ref.read(appTextProvider)),
      );
    }
  }

  /// The Cloudflare dial that carried traffic last, if the store can say.
  CdnDial? _lastCdnDial() {
    try {
      return ref.read(lastCdnDialProvider).read();
    } on Object {
      return null;
    }
  }

  Future<void> _connectXray({
    required int attempt,
    required String deviceId,
    required String serverCode,
    required String protocolProfileCode,
    bool trySaved = true,
    List<CdnDial>? cdnDials,
  }) async {
    state = state.copyWith(isSubmitting: true, actionErrorMessage: () => null);
    try {
      final XrayCredentialStore credentials = ref.read(
        xrayCredentialStoreProvider,
      );
      XrayClientResult result;
      bool fromSavedCredential = false;
      // The credential this phone already holds, first: the server hands the
      // same one back on every request, so asking before connecting only
      // adds a round trip to an API the network may be slowing -- 30 s on a
      // filtered day, against v2rayNG's instant start from its saved config
      // (2026-10-18). The server is asked afterwards, in the background; a
      // saved credential that carries nothing is replaced by asking first.
      final XrayClientResult? saved = trySaved
          ? await _recalled(
              credentials,
              serverCode: serverCode,
              profileCode: protocolProfileCode,
            )
          : null;
      final bool usedSaved = saved != null;
      if (saved != null) {
        result = saved;
      } else {
        try {
          result = await runGuarded(
            ref,
            () => _repository.requestXrayClient(
              deviceId: deviceId,
              serverCode: serverCode,
              protocolProfileCode: protocolProfileCode,
            ),
          );
          await _remember(
            credentials,
            serverCode: serverCode,
            profileCode: protocolProfileCode,
            credential: result,
          );
        } on NebulaConnectivityException {
          // Nobody answered. The credential already on this phone is a UUID on
          // an inbound and stays valid until an admin revokes it, so the tunnel
          // can still come up -- which is the whole point when the API's
          // address is blocked and the tunnel is the only way back to it.
          //
          // ponytail: not re-checked with the server, because there is no
          // server to ask. A credential revoked in the meantime would raise a
          // tunnel that carries nothing, so the app says plainly that this
          // connection was made from saved credentials. If that becomes a real
          // failure rather than a theoretical one, probe through the local
          // proxy before reporting connected.
          final XrayClientResult? saved = await _recalled(
            credentials,
            serverCode: serverCode,
            profileCode: protocolProfileCode,
          );
          if (saved == null) {
            rethrow;
          }
          result = saved;
          fromSavedCredential = true;
        }
      }
      if (!ref.mounted) {
        return;
      }
      if (_cancelled(attempt)) {
        await _undoCancelledConnect(
          deviceId: deviceId,
          serverCode: serverCode,
          profileCode: protocolProfileCode,
          xray: true,
          tunnelStarted: false,
        );
        return;
      }
      // Same honesty invariant as the WireGuard path -- the server-side
      // client is provisioned regardless of what happens next.
      state = state.copyWith(
        xrayClient: () => result,
        fromSavedCredential: fromSavedCredential,
        connectedServerCode: () => serverCode,
        activeProtocolCode: () =>
            _protocolCodeFor(protocolProfileCode) ?? protocolProfileCode,
        activeProfileCode: () => protocolProfileCode,
      );

      // Read at connect time, not watched: the config is built once per
      // connection, and watching would rebuild the controller and drop a live
      // tunnel whenever a setting changed. Held here so the state can record
      // the routing this connection was actually built with.
      final AdvancedSettings settings = ref.read(
        advancedSettingsControllerProvider,
      );
      // Through Cloudflare, the dials still to try for this credential: the
      // one that carried traffic last first (see CdnDial).
      final List<CdnDial> dials = isCloudflareRoute(result)
          ? cdnDials ??
                cdnDialOrder(
                  lastWorked: _lastCdnDial(),
                  hasIpv6: await ref.read(deviceHasIpv6Provider)(),
                )
          : const <CdnDial>[CdnDial.asGiven];
      final CdnDial dial = dials.first;
      bool tunnelUp = false;
      String? tunnelError;
      final bool proxyMode =
          settings.connectionMode == ConnectionMode.localProxy;
      LocalProxy? runningProxy;
      try {
        await _stopLeftoverTunnel();
        // A local proxy needs no VPN consent, but it does need its port:
        // another app already listening there would leave the engine
        // unable to start, reported as nothing more than a failed connect.
        final bool portTaken =
            proxyMode &&
            await ref.read(loopbackPortProbeProvider)(settings.localProxyPort);
        final bool granted = proxyMode || await _xrayTunnel.requestPermission();
        if (portTaken) {
          tunnelError = ref
              .read(appTextProvider)
              .errorProxyPortInUse('${settings.localProxyPort}');
        } else if (!granted) {
          tunnelError = ref.read(appTextProvider).vpnPermissionNotGranted;
        } else {
          final LocalProxy localProxy = proxyMode
              ? await ref
                    .read(localProxyAccountStoreProvider)
                    .readOrCreate(settings.localProxyPort)
              : await ref.read(localProxyFactoryProvider)();
          _tunnelProxy = proxyMode ? null : localProxy;
          await ref.read(echServerRefreshProvider)(echConfigListFor(result));
          await _xrayTunnel.connect(
            renderXrayClientConfigJson(
              result,
              settings: settings,
              localProxy: localProxy,
              apiHosts: ref.read(apiHostsProvider),
              cdnDial: dial,
            ),
            excludedPackages: _excludedPackages,
            killSwitch: ref
                .read(protectionControllerProvider)
                .blockWhenVpnDrops,
            routes: _routes,
            // What people chose, not an internal code: it is the title in
            // the shade and the name in Android's own VPN line.
            sessionName: state.selectedServer?.displayName ?? serverCode,
            notificationShowsSpeed: ref
                .read(protectionControllerProvider)
                .notificationSpeed,
            disconnectLabel: ref.read(appTextProvider).ctaDisconnect,
            proxyOnly: proxyMode,
          );
          tunnelUp = true;
          runningProxy = proxyMode ? localProxy : null;
        }
      } catch (error) {
        tunnelError = userFacingErrorMessage(error, ref.read(appTextProvider));
      }

      if (!ref.mounted) {
        return;
      }
      // A local proxy carries only what is sent to it, so there is nothing
      // to check from here; a tunnel carries this app's requests too.
      if (!_cancelled(attempt) &&
          tunnelUp &&
          runningProxy == null &&
          !await _tunnelCarriesTraffic(attempt) &&
          !_cancelled(attempt)) {
        // Xray's tunnel is up the moment the engine starts, whether or not
        // the server is there. Seen on Windows with saved credentials for a
        // server that was gone: "Protected" for a minute and a half while
        // every lookup failed. Undo it, as WireGuard's missing handshake is.
        if (!ref.mounted) {
          return;
        }
        state = state.copyWith(isSubmitting: false, tunnelEstablished: true);
        await disconnect(deviceId);
        // The same credential through Cloudflare, dialled the next way: each
        // of Iran's firewalls lets a different shape through.
        if (dials.length > 1 && !_cancelled(attempt)) {
          await _connectXray(
            attempt: attempt,
            deviceId: deviceId,
            serverCode: serverCode,
            protocolProfileCode: protocolProfileCode,
            cdnDials: dials.sublist(1),
          );
          return;
        }
        // A saved credential the server has since changed carries nothing:
        // ask the server, as every connect used to, and try once more only
        // if it hands out something different. The same one again would
        // just double the wait on a network that blocks this protocol.
        if (usedSaved &&
            !_cancelled(attempt) &&
            await _serverChangedCredential(
              deviceId: deviceId,
              serverCode: serverCode,
              profileCode: protocolProfileCode,
              saved: result,
            ) &&
            !_cancelled(attempt)) {
          await _connectXray(
            attempt: attempt,
            deviceId: deviceId,
            serverCode: serverCode,
            protocolProfileCode: protocolProfileCode,
          );
          return;
        }
        // Nothing gets through a tunnel on a device that is not online at
        // all either -- in offline mode, from a saved credential, nothing
        // else would have noticed. That is not a blocked protocol, and the
        // next protocol would not help.
        // Off screen on Android this app's own requests may be held back
        // (see trafficCheckMeaningfulProvider): a connect finished there
        // called an online phone offline (2026-10-29). Its checks are not
        // asked, and the failure is put as what is known -- nothing got
        // through the tunnel.
        final bool inFront = ref.read(trafficCheckMeaningfulProvider)();
        final bool online = !inFront || await ref.read(deviceOnlineProvider)();
        // Online: then which step to the server failed, if any, says more
        // than "may be blocking it" (roadmap 79).
        // The tunnel's address came from the API's route in use. Asked again
        // over the next one (a CDN, a web-host front), the API hands out a
        // tunnel through that one instead -- the way past an address that is
        // throttled rather than blocked.
        if (online &&
            ref.read(moveApiRouteProvider)() &&
            !_cancelled(attempt)) {
          await _connectXray(
            attempt: attempt,
            deviceId: deviceId,
            serverCode: serverCode,
            protocolProfileCode: protocolProfileCode,
          );
          return;
        }
        final ServerReach reach = online && inFront
            ? await ref.read(serverReachProvider)(result)
            : ServerReach.reachable;
        if (ref.mounted) {
          final AppText text = ref.read(appTextProvider);
          state = state.copyWith(
            actionErrorMessage: () => !online
                ? text.errorOffline
                : switch (reach) {
                    ServerReach.nameNotFound => text.errorServerNameNotFound,
                    ServerReach.unreachable => text.errorServerUnreachable,
                    ServerReach.certificateRejected =>
                      text.errorServerCertificate,
                    ServerReach.reachable => text.errorTunnelNoTraffic,
                  },
          );
        }
        return;
      }
      if (!ref.mounted) {
        return;
      }
      if (_cancelled(attempt)) {
        await _undoCancelledConnect(
          deviceId: deviceId,
          serverCode: serverCode,
          profileCode: protocolProfileCode,
          xray: true,
          tunnelStarted: tunnelUp,
        );
        return;
      }
      if (tunnelUp && isCloudflareRoute(result)) {
        try {
          await ref.read(lastCdnDialProvider).write(dial);
        } on Object {
          // A hint for next time; the connection does not depend on it.
        }
      }
      state = state.copyWith(
        isSubmitting: false,
        tunnelEstablished: tunnelUp,
        // Recorded only when this process saw the tunnel come up, so a
        // session it did not start reports no elapsed time rather than a
        // wrong one.
        tunnelEstablishedAt: () => tunnelUp ? DateTime.now() : null,
        sanctionsOnly: tunnelUp && routesSanctionsOnly(result, settings),
        localProxy: () => runningProxy,
        actionErrorMessage: () => tunnelError,
      );
      if (tunnelUp) {
        _watchTunnel();
        await _recordConnection();
        // What the Cloudflare address scan tests. Learned here, on every
        // CDN connection: learned only by opening that screen while
        // connected, a connect-then-disconnect left it saying "connect
        // once" (reported 2026-10-18).
        if (cdnTransports.contains(result.transport)) {
          unawaited(
            ref
                .read(advancedSettingsControllerProvider.notifier)
                .rememberCdnHost(result.serverAddress),
          );
        }
        if (usedSaved) {
          unawaited(
            _confirmWithServer(
              deviceId: deviceId,
              serverCode: serverCode,
              profileCode: protocolProfileCode,
            ),
          );
        }
      }
    } catch (error) {
      if (!ref.mounted || _cancelled(attempt)) {
        return;
      }
      state = state.copyWith(
        isSubmitting: false,
        actionErrorMessage: () =>
            userFacingErrorMessage(error, ref.read(appTextProvider)),
      );
    }
  }

  /// Takes down a tunnel this app left running, before starting another.
  ///
  /// A tunnel outlives the screen that started it, so reopening the app
  /// can find one up that this run knows nothing about. The Xray plugin
  /// cannot start over it: it stops the old service, starts the core,
  /// reports CONNECTED -- and then the old service's shutdown lands on the
  /// new core. On the phone that read "Protected" with no tunnel at all.
  ///
  /// So stop first, and wait until Android no longer lists a VPN: the same
  /// sequence as disconnecting and connecting again by hand, which works.
  /// Only when this app holds VPN consent, because consent is held by one
  /// app at a time -- a VPN that is up while this app holds it is this
  /// app's, and anyone else's is left for Android's own consent dialog.
  ///
  /// Never fails a connect. The wait is bounded: a WireGuard tunnel from an
  /// earlier run belongs to a backend object that is gone and cannot be
  /// stopped from here, and the watch started after connecting reports
  /// honestly on whatever happens next.
  @override
  Future<void> _stopLeftoverTunnel() async {
    try {
      // Unknown is stopped too: the stops below only ever reach this app's
      // own engines, so they cannot take anyone else's VPN down.
      final VpnOwner? vpn = await _tunnel.activeVpn();
      final int? proxyPort = (await _records.read())?.localProxyPort;
      final Future<bool> Function(int) portOpen = ref.read(
        loopbackPortProbeProvider,
      );
      final bool proxyUp = proxyPort != null && await portOpen(proxyPort);
      if (!proxyUp && (vpn == VpnOwner.none || vpn == VpnOwner.other)) {
        return;
      }
      _stopWatchingTunnel();
      for (final Future<void> Function() stop in <Future<void> Function()>[
        _xrayTunnel.disconnect,
        _tunnel.disconnect,
      ]) {
        try {
          await stop();
        } catch (_) {
          // The other engine may be the one that was running.
        }
      }
      final Duration step = ref.read(tunnelSettleStepProvider);
      for (int waited = 0; waited < 25; waited++) {
        final bool stillProxy = proxyPort != null && await portOpen(proxyPort);
        if (!stillProxy && await _tunnel.activeVpn() != VpnOwner.own) {
          break;
        }
        await Future<void>.delayed(step);
      }
      await _forgetConnection();
      // The interface closes a moment before the old service is destroyed,
      // and its teardown stops whatever core is running in the process --
      // including a new one started in that moment.
      await Future<void>.delayed(step * 4);
    } catch (_) {
      // A question the platform could not answer is not a reason to refuse
      // to connect.
    }
  }

  /// Replaces a connection raised from a saved credential with a fresh one,
  /// once the server can be reached again.
  ///
  /// Measured on a phone: a tunnel raised while the phone had no network at
  /// all -- connect-on-launch in airplane mode -- never carried traffic after
  /// the network came back, while one raised online survived the same drop.
  /// Reconnecting as soon as the server answers again fixes that, and swaps a
  /// credential nobody confirmed for one the server just issued.
  ///
  /// Does nothing for a connection the server already issued, or while the
  /// server stays unreachable -- then the saved credential is all there is.
  Future<void> refreshAfterOffline(String? deviceId) async {
    if (deviceId == null ||
        !state.fromSavedCredential ||
        !state.tunnelEstablished ||
        state.isSubmitting) {
      return;
    }
    await disconnect(deviceId);
    await connect(deviceId);
  }

  @override
  Future<void> disconnect(String deviceId) async {
    final String? serverCode = state.connectedServerCode;
    if (serverCode == null) {
      return;
    }
    final String? protocolCode = state.activeProtocolCode;
    final bool isXray = protocolCode != wireguardProtocolCode;

    state = state.copyWith(isSubmitting: true, actionErrorMessage: () => null);
    // Best-effort: tear down the local tunnel first so traffic stops
    // flowing before a WireGuard peer is revoked, but a failure here must
    // not block revoking it.
    if (state.tunnelEstablished) {
      try {
        if (isXray) {
          await _xrayTunnel.disconnect();
        } else {
          await _tunnel.disconnect();
        }
        // Removing the VPN interface makes Android briefly report no
        // active network while it switches the default route back to
        // WiFi/cellular -- confirmed live: the very next call (the revoke
        // request below) would otherwise race that switch and fail with a
        // spurious "you're offline", even though the underlying network
        // was fine seconds later. This settling delay gives the OS the
        // brief window it needs before the revoke call below runs.
        await Future<void>.delayed(const Duration(milliseconds: 600));
        await _forgetConnection();
      } catch (_) {
        // Fall through to the server-side revoke regardless.
      }
    }
    final String? profileCode = state.activeProfileCode;
    if (isXray && profileCode == null) {
      // An Xray connection should always have set activeProfileCode
      // alongside activeProtocolCode -- treat this as already disconnected
      // rather than sending a malformed revoke.
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
      );
      return;
    }
    try {
      // An Xray credential is kept: the server hands the same one back on the
      // next connect, and the saved copy is what an offline connect uses. It
      // is revoked on sign-out, by an admin, or when the account's access or
      // data runs out -- all on the server, for every credential the device
      // holds.
      if (!isXray) {
        await runGuarded(
          ref,
          () => _repository.revokePeer(
            deviceId: deviceId,
            serverCode: serverCode,
          ),
        );
      }
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
      );
    } catch (error) {
      state = state.copyWith(
        isSubmitting: false,
        actionErrorMessage: () =>
            userFacingErrorMessage(error, ref.read(appTextProvider)),
      );
    }
  }

  /// Looks up the currently selected server's profile to find which
  /// protocol it provisions -- the picker only tracks profile codes, not
  /// protocol codes, so this is the one place that needs to cross-reference
  /// [DevicesState.selectedServer].
  String? _protocolCodeFor(String profileCode) {
    for (final AvailableProfile profile
        in state.selectedServer?.profiles ?? const <AvailableProfile>[]) {
      if (profile.code == profileCode) {
        return profile.protocolCode;
      }
    }
    return null;
  }
}
