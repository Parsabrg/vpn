/// The caller's identity, as returned by `GET /v1/auth/me`.
///
/// [deviceId] is the only place the app ever learns its server-assigned
/// device id -- it must be persisted (see `DeviceIdStore`) and sent on every
/// subsequent login from this install.
class UserPrincipal {
  const UserPrincipal({
    required this.userId,
    required this.sessionId,
    required this.deviceId,
  });

  final String userId;
  final String sessionId;
  final String deviceId;
}
