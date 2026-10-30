part of 'devices_controller.dart';

/// Credentials: confirming them with the server, keeping and recalling
/// them, revoking them, and checking the account still has access.
mixin _Credentials on _DevicesCore {
  /// Asks the server for this protocol's credential and saves it. True when
  /// it differs from [saved] in anything the connection is made with.
  @override
  Future<bool> _serverChangedCredential({
    required String deviceId,
    required String serverCode,
    required String profileCode,
    required XrayClientResult saved,
  }) async {
    try {
      final XrayClientResult fresh = await runGuarded(
        ref,
        () => _repository.requestXrayClient(
          deviceId: deviceId,
          serverCode: serverCode,
          protocolProfileCode: profileCode,
        ),
      );
      await _remember(
        ref.read(xrayCredentialStoreProvider),
        serverCode: serverCode,
        profileCode: profileCode,
        credential: fresh,
      );
      return fresh.uuid != saved.uuid ||
          fresh.serverAddress != saved.serverAddress ||
          fresh.port != saved.port ||
          fresh.sni != saved.sni ||
          fresh.transport != saved.transport ||
          fresh.path != saved.path ||
          fresh.password != saved.password;
    } catch (_) {
      return false;
    }
  }

  /// After a connect from the saved credential: the request every connect
  /// used to make first. What the server says still counts -- an allowance
  /// used up, access expired, the server in maintenance, the client revoked
  /// -- and takes the connection down with its reason. Not reaching the
  /// server changes nothing: the tunnel already proved it carries traffic.
  @override
  Future<void> _confirmWithServer({
    required String deviceId,
    required String serverCode,
    required String profileCode,
  }) async {
    try {
      final XrayClientResult fresh = await runGuarded(
        ref,
        () => _repository.requestXrayClient(
          deviceId: deviceId,
          serverCode: serverCode,
          protocolProfileCode: profileCode,
        ),
      );
      await _remember(
        ref.read(xrayCredentialStoreProvider),
        serverCode: serverCode,
        profileCode: profileCode,
        credential: fresh,
      );
    } on NebulaConnectivityException {
      // Kept: see above. Said on screen, as for any connection the server
      // did not confirm, and replaced once it answers (refreshAfterOffline).
      if (ref.mounted && state.activeProfileCode == profileCode) {
        state = state.copyWith(fromSavedCredential: true);
      }
    } on NebulaApiException catch (error) {
      // Only a definite no takes a working tunnel down. A sign-in that could
      // not be renewed (401), a busy server (429, 5xx) or a conflict says
      // nothing about this connection: treated as a refusal, a token refresh
      // failing on a flaky network dropped the phone's tunnel over and over
      // (2026-10-19).
      final bool refused =
          error.isQuotaExhausted ||
          error.isServerMaintenance ||
          error.isAccountExpired ||
          error.statusCode == 400 ||
          error.statusCode == 404;
      if (!refused ||
          !ref.mounted ||
          !state.tunnelEstablished ||
          state.activeProfileCode != profileCode) {
        return;
      }
      await disconnect(deviceId);
      if (ref.mounted) {
        state = state.copyWith(
          actionErrorMessage: () =>
              userFacingErrorMessage(error, ref.read(appTextProvider)),
        );
      }
    } catch (_) {
      // Anything else is not the server's answer; keep the connection.
    }
  }

  /// Revokes a client on the server and forgets any saved copy of it.
  ///
  /// The two go together or the saved copy lies: a later offline connect
  /// from it raises a tunnel on a credential the server no longer accepts --
  /// carrying nothing while the app says it is connected. Measured on a phone
  /// when Disconnect still revoked.
  @override
  Future<void> _revokeXrayClient({
    required String deviceId,
    required String serverCode,
    required String protocolProfileCode,
  }) async {
    await _repository.revokeXrayClient(
      deviceId: deviceId,
      serverCode: serverCode,
      protocolProfileCode: protocolProfileCode,
    );
    try {
      await ref
          .read(xrayCredentialStoreProvider)
          .forget(serverCode: serverCode, profileCode: protocolProfileCode);
    } catch (_) {
      // A copy that could not be deleted is refused later anyway: the server
      // no longer knows the credential, and this is not worth failing a
      // disconnect over.
    }
  }

  /// Keeps the credential for a connect the server cannot answer later.
  ///
  /// Storage failing is never a reason to refuse a connection that is
  /// otherwise fine: the keystore can be unavailable (a device mid-upgrade,
  /// a headless test), and the cost is only that the next offline connect
  /// has nothing to fall back on.
  @override
  Future<void> _remember(
    XrayCredentialStore store, {
    required String serverCode,
    required String profileCode,
    required XrayClientResult credential,
  }) async {
    try {
      await store.write(
        serverCode: serverCode,
        profileCode: profileCode,
        credential: credential,
      );
    } catch (_) {
      // Deliberately swallowed; see above.
    }
  }

  /// The counterpart: an unreadable store means no saved credential, which
  /// the caller already handles.
  @override
  Future<XrayClientResult?> _recalled(
    XrayCredentialStore store, {
    required String serverCode,
    required String profileCode,
  }) async {
    try {
      return await store.read(serverCode: serverCode, profileCode: profileCode);
    } catch (_) {
      return null;
    }
  }

  /// Stops a tunnel whose access has ended, and says why.
  ///
  /// The server takes credentials away within about a minute of access
  /// ending -- an allowance spent, the account or a grant expired, the
  /// device revoked, the account disabled. The tunnel on this device then
  /// carries nothing, and nothing on the device says so: the VPN is still
  /// up, so the screen went on showing "Protected". Asking the server is the
  /// only way to find out, and this app's own requests bypass the tunnel, so
  /// the question still gets through.
  ///
  /// Quiet when the answer does not arrive -- offline, or the API busy --
  /// because a tunnel is not stopped on an answer nobody gave.
  @override
  Future<void> _checkAccess() async {
    // With no server there is no access to end, and nobody to ask: a build
    // that also carries a server's address would be told "not signed in"
    // and take the tunnel down for it.
    // Nor on one of this device's own links, which an account's allowance,
    // expiry or devices have nothing to do with.
    // Only with the app in front of the person (on Android), like the
    // traffic check, and once more when it comes back: two API requests
    // every 30 seconds kept the phone's radio awake all night -- 35 minutes
    // of it for under 100 MB in 2.5 hours, measured. The server refuses a
    // revoked device or an ended account by itself; this is only how the
    // screen finds out sooner.
    if (_checkingAccess ||
        !state.tunnelEstablished ||
        !ref.read(trafficCheckMeaningfulProvider)() ||
        ref.read(freeModeProvider) ||
        isOwnLinkCode(state.connectedServerCode)) {
      return;
    }
    _checkingAccess = true;
    try {
      final AccountRepository accounts = ref.read(accountRepositoryProvider);
      final AccountSummary account;
      final List<AccountDevice> devices;
      try {
        account = await accounts.fetchAccount();
        devices = await accounts.listDevices();
      } on NebulaApiException catch (error) {
        if (!ref.mounted) {
          return;
        }
        // A 401 ends the tunnel only once the sign-in has really expired: a
        // refresh refused for a reason that is not the session (a 429 or a
        // 503) used to arrive here as the 401 it followed, and took a
        // connected tunnel down with the user still signed in (2026-10-30).
        if ((error.statusCode == 401 && !ref.read(stillSignedInProvider)()) ||
            error.statusCode == 403) {
          // The session is over, not merely unreachable: the device was
          // revoked or the account disabled. Signing out follows; the tunnel
          // goes now, without asking a server that will not answer.
          await _endTunnel(reason: null, revokeOnServer: false);
        }
        return;
      } on Object {
        return;
      }
      if (!ref.mounted || !state.tunnelEstablished) {
        return;
      }
      final AppText text = ref.read(appTextProvider);
      final String? reason;
      if (account.isMetered && (account.remainingBytes ?? 0) <= 0) {
        reason = text.errorQuotaExhausted;
      } else if (account.hasExpiredAt(DateTime.now())) {
        reason = text.accessExpired;
      } else if (!_holdsAccess(devices)) {
        if (await _retryRevokedCredential()) {
          return;
        }
        reason = text.errorAccessEnded;
      } else {
        reason = null;
      }
      if (reason != null) {
        await _endTunnel(reason: reason, revokeOnServer: true);
      }
    } finally {
      _checkingAccess = false;
    }
  }

  /// The server no longer lists this device's credential, but still offers
  /// the server: the credential was revoked, not the access. A saved copy
  /// the server had pruned raised a working tunnel, and "Your access to this
  /// server has ended" followed seconds later (phone, 2026-10-30). Forgets
  /// it and connects afresh, once in ten minutes; access that has really
  /// ended is refused by that connect, or ends at the next check.
  Future<bool> _retryRevokedCredential() async {
    final String? server = state.connectedServerCode;
    final String? profile = state.activeProfileCode;
    final String? deviceId = _connectedDeviceId ?? _storedDeviceId();
    final DateTime now = DateTime.now();
    final DateTime? last = _lastCredentialRetry;
    if (server == null ||
        profile == null ||
        deviceId == null ||
        !state.servers.any((AvailableServer s) => s.code == server) ||
        (last != null && now.difference(last) < const Duration(minutes: 10))) {
      return false;
    }
    _lastCredentialRetry = now;
    // Every saved credential for the server, not only the one in use: the
    // others came from the same place, and Automatic picked the next stale
    // one -- saved while the server ran as its own installation -- and
    // ended the same way a minute later (2026-10-30).
    final XrayCredentialStore store = ref.read(xrayCredentialStoreProvider);
    final AvailableServer? listed = state.servers
        .where((AvailableServer s) => s.code == server)
        .firstOrNull;
    for (final String code in <String>{
      profile,
      ...?listed?.profiles.map((AvailableProfile p) => p.code),
    }) {
      try {
        await store.forget(serverCode: server, profileCode: code);
      } catch (_) {
        // Asked afresh all the same.
      }
    }
    await _endTunnel(reason: null, revokeOnServer: false);
    if (ref.mounted) {
      await connect(deviceId);
    }
    return true;
  }

  /// Whether this device still holds a live credential on the server it is
  /// connected to -- which is what an expired grant, an admin, or the server
  /// pruning it takes away. A device no longer listed has been revoked.
  bool _holdsAccess(List<AccountDevice> devices) {
    final String? server = state.connectedServerCode;
    // One of this device's own links: no account is behind it.
    if (isOwnLinkCode(server)) {
      return true;
    }
    for (final AccountDevice device in devices) {
      if (device.isCurrent) {
        return server == null || device.serverCodes.contains(server);
      }
    }
    return false;
  }

  /// Reuses this install's existing WireGuard identity if one was already
  /// generated, rather than minting a new key pair (and therefore a new
  /// peer identity) on every connect attempt.
  @override
  Future<WireGuardKeyPair> _currentOrNewKeyPair() async {
    final String? storedPrivateKey = await _keyStore.readPrivateKey();
    if (storedPrivateKey != null) {
      return _keyGenerator.fromStoredPrivateKey(storedPrivateKey);
    }
    final WireGuardKeyPair generated = await _keyGenerator.generate();
    await _keyStore.writePrivateKey(generated.privateKeyBase64);
    return generated;
  }
}
