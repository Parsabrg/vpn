/// Named path constants so routes are never scattered as string literals.
abstract final class RoutePaths {
  static const String splash = '/splash';

  /// First launch of a generic build, and after "Change server".
  static const String pair = '/pair';
  static const String signIn = '/sign-in';
  static const String accountRequest = '/account-request';
  static const String activate = '/activate';
  static const String passwordReset = '/password-reset';
  static const String passwordResetConfirm = '/password-reset/confirm';

  static const String homeConnect = '/home/connect';
  static const String homeDevices = '/home/devices';
  static const String homeAccount = '/home/account';
  static const String homeChangePassword = '/home/account/password';
  static const String homeDeleteAccount = '/home/account/delete';

  /// Pushed from Account rather than being a tab: somewhere you go to
  /// change something and then leave.
  static const String homeSettings = '/home/settings';

  /// Pushed from Settings. Its own route rather than a dialog: the list runs
  /// to hundreds of rows and is something people come back to.
  static const String homeSplitTunnel = '/home/settings/split-tunnel';
  static const String homeBypassDomains = '/home/settings/bypass-domains';
  static const String homeCleanIp = '/home/settings/clean-ip';

  /// Pushed from Settings. Somewhere you go when a connection is not working.
  static const String homeConnectionLog = '/home/settings/log';
  static const String homeDiagnostics = '/home/settings/diagnostics';

  /// Pushed from Settings: the knobs that change what the core is told to do.
  static const String homeAdvanced = '/home/settings/advanced';

  /// Reachable while unauthenticated; every other route requires a session.
  static const Set<String> unauthenticatedReachable = <String>{
    pair,
    signIn,
    accountRequest,
    activate,
    passwordReset,
    passwordResetConfirm,
  };

  /// Default landing tab once authenticated. Connect, because it is the
  /// reason the app is opened.
  static const String homeDefault = homeConnect;
}
