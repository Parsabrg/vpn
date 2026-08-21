/// Named path constants so routes are never scattered as string literals.
abstract final class RoutePaths {
  static const String splash = '/splash';
  static const String signIn = '/sign-in';
  static const String accountRequest = '/account-request';
  static const String activate = '/activate';
  static const String passwordReset = '/password-reset';
  static const String passwordResetConfirm = '/password-reset/confirm';

  static const String homeDevices = '/home/devices';
  static const String homeAccount = '/home/account';
  static const String homeSettings = '/home/settings';

  /// Reachable while unauthenticated; every other route requires a session.
  static const Set<String> unauthenticatedReachable = <String>{
    signIn,
    accountRequest,
    activate,
    passwordReset,
    passwordResetConfirm,
  };

  /// Default landing tab once authenticated.
  static const String homeDefault = homeDevices;
}
