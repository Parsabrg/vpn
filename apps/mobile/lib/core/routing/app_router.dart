import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../features/account/account_screen.dart';
import '../../features/account/account_security_screens.dart';
import '../../features/account_request/account_request_screen.dart';
import '../../features/activation/activation_screen.dart';
import '../../features/auth/sign_in_screen.dart';
import '../../features/connect/connect_screen.dart';
import '../../features/devices/devices_screen.dart';
import '../../features/free/free_mode_screen.dart';
import '../../features/home/home_shell.dart';
import '../../features/pairing/pairing_screen.dart';
import '../../features/password_reset/password_reset_confirm_screen.dart';
import '../../features/password_reset/password_reset_request_screen.dart';
import '../../features/settings/advanced_settings_screen.dart';
import '../../features/settings/bypass_domains_screen.dart';
import '../../features/settings/clean_ip_screen.dart';
import '../../features/settings/connection_log_screen.dart';
import '../../features/settings/diagnostics_screen.dart';
import '../../features/settings/settings_screen.dart';
import '../../features/settings/split_tunnel_screen.dart';
import '../../features/splash/splash_screen.dart';
import '../auth/auth_notifier.dart';
import '../auth/auth_state.dart';
import '../free/free_mode.dart';
import '../pairing/pairing.dart';
import '../pairing/pairing_providers.dart';
import 'nebula_page.dart';
import 'route_paths.dart';

/// Bridges Riverpod's [authNotifierProvider] changes into GoRouter's
/// `refreshListenable`, so a state transition (sign-in, logout, session
/// expiry) re-runs [_redirect] without any screen having to navigate
/// imperatively.
class _AuthRefreshListenable extends ChangeNotifier {
  _AuthRefreshListenable(Ref ref) {
    ref.listen<AuthState>(
      authNotifierProvider,
      (AuthState? previous, AuthState next) => notifyListeners(),
    );
    ref.listen<Pairing?>(
      pairingProvider,
      (Pairing? previous, Pairing? next) => notifyListeners(),
    );
    ref.listen<bool>(
      freeModeProvider,
      (bool? previous, bool next) => notifyListeners(),
    );
  }
}

String? _redirect(Ref ref, GoRouterState state) {
  final AuthState authState = ref.read(authNotifierProvider);
  final String location = state.matchedLocation;

  // With no server there is nothing to pair with or sign in to: the app is
  // open, and the door screens lead back into it.
  if (ref.read(freeModeProvider)) {
    return location == RoutePaths.splash ||
            RoutePaths.unauthenticatedReachable.contains(location)
        ? RoutePaths.homeDefault
        : null;
  }

  // Unpaired, there is no server to sign in to or connect through: pairing
  // comes before everything else, whatever the session says.
  if (ref.read(pairingProvider) == null) {
    return location == RoutePaths.pair ? null : RoutePaths.pair;
  }

  switch (authState) {
    case AuthAuthenticating():
      return location == RoutePaths.splash ? null : RoutePaths.splash;
    // A stored session and nobody answering is not a reason to hold someone
    // at the door. It used to be: the splash explained the server was
    // unreachable and offered to retry, and that was the whole app until it
    // answered. On a blocked address it never does -- and the tunnel, which
    // is the only thing that could reach it again, was on the other side of
    // that screen. The app opens on its saved settings instead, and says
    // where it stands.
    case AuthUnreachable():
      return location == RoutePaths.splash ||
              RoutePaths.unauthenticatedReachable.contains(location)
          ? RoutePaths.homeDefault
          : null;
    case AuthUnauthenticated():
    case AuthSessionExpired():
      if (RoutePaths.unauthenticatedReachable.contains(location)) {
        return null;
      }
      return RoutePaths.signIn;
    case AuthAuthenticated():
      final bool onUnauthenticatedOnlyRoute =
          location == RoutePaths.splash ||
          RoutePaths.unauthenticatedReachable.contains(location);
      return onUnauthenticatedOnlyRoute ? RoutePaths.homeDefault : null;
  }
}

final routerProvider = Provider<GoRouter>((Ref ref) {
  final _AuthRefreshListenable refreshListenable = _AuthRefreshListenable(ref);
  ref.onDispose(refreshListenable.dispose);

  return GoRouter(
    initialLocation: RoutePaths.splash,
    refreshListenable: refreshListenable,
    redirect: (BuildContext context, GoRouterState state) =>
        _redirect(ref, state),
    routes: <RouteBase>[
      GoRoute(
        path: RoutePaths.splash,
        pageBuilder: (BuildContext context, GoRouterState state) =>
            buildNebulaPage(context, state, const SplashScreen()),
      ),
      GoRoute(
        path: RoutePaths.pair,
        pageBuilder: (BuildContext context, GoRouterState state) =>
            buildNebulaPage(context, state, const PairingScreen()),
      ),
      GoRoute(
        path: RoutePaths.signIn,
        pageBuilder: (BuildContext context, GoRouterState state) =>
            buildNebulaPage(context, state, const SignInScreen()),
      ),
      GoRoute(
        path: RoutePaths.accountRequest,
        pageBuilder: (BuildContext context, GoRouterState state) =>
            buildNebulaPage(context, state, const AccountRequestScreen()),
      ),
      GoRoute(
        path: RoutePaths.activate,
        pageBuilder: (BuildContext context, GoRouterState state) =>
            buildNebulaPage(context, state, const ActivationScreen()),
      ),
      GoRoute(
        path: RoutePaths.passwordReset,
        pageBuilder: (BuildContext context, GoRouterState state) =>
            buildNebulaPage(context, state, const PasswordResetRequestScreen()),
      ),
      GoRoute(
        path: RoutePaths.passwordResetConfirm,
        pageBuilder: (BuildContext context, GoRouterState state) =>
            buildNebulaPage(context, state, const PasswordResetConfirmScreen()),
      ),
      StatefulShellRoute.indexedStack(
        builder:
            (
              BuildContext context,
              GoRouterState state,
              StatefulNavigationShell navigationShell,
            ) => HomeShell(navigationShell: navigationShell),
        branches: <StatefulShellBranch>[
          StatefulShellBranch(
            routes: <RouteBase>[
              GoRoute(
                path: RoutePaths.homeConnect,
                builder: (BuildContext context, GoRouterState state) =>
                    const ConnectScreen(),
              ),
            ],
          ),
          StatefulShellBranch(
            routes: <RouteBase>[
              GoRoute(
                path: RoutePaths.homeDevices,
                builder: (BuildContext context, GoRouterState state) =>
                    const DevicesScreen(),
              ),
            ],
          ),
          StatefulShellBranch(
            routes: <RouteBase>[
              GoRoute(
                path: RoutePaths.homeAccount,
                builder: (BuildContext context, GoRouterState state) =>
                    ref.read(freeModeProvider)
                    ? const FreeModeScreen()
                    : const AccountScreen(),
              ),
            ],
          ),
        ],
      ),
      GoRoute(
        path: RoutePaths.homeSettings,
        pageBuilder: (BuildContext context, GoRouterState state) =>
            buildNebulaPage(context, state, const SettingsScreen()),
      ),
      GoRoute(
        path: RoutePaths.homeChangePassword,
        pageBuilder: (BuildContext context, GoRouterState state) =>
            buildNebulaPage(context, state, const ChangePasswordScreen()),
      ),
      GoRoute(
        path: RoutePaths.homeDeleteAccount,
        pageBuilder: (BuildContext context, GoRouterState state) =>
            buildNebulaPage(context, state, const DeleteAccountScreen()),
      ),
      GoRoute(
        path: RoutePaths.homeSplitTunnel,
        pageBuilder: (BuildContext context, GoRouterState state) =>
            buildNebulaPage(context, state, const SplitTunnelScreen()),
      ),
      GoRoute(
        path: RoutePaths.homeBypassDomains,
        pageBuilder: (BuildContext context, GoRouterState state) =>
            buildNebulaPage(context, state, const BypassDomainsScreen()),
      ),
      GoRoute(
        path: RoutePaths.homeCleanIp,
        pageBuilder: (BuildContext context, GoRouterState state) =>
            buildNebulaPage(context, state, const CleanIpScreen()),
      ),
      GoRoute(
        path: RoutePaths.homeConnectionLog,
        pageBuilder: (BuildContext context, GoRouterState state) =>
            buildNebulaPage(context, state, const ConnectionLogScreen()),
      ),
      GoRoute(
        path: RoutePaths.homeDiagnostics,
        pageBuilder: (BuildContext context, GoRouterState state) =>
            buildNebulaPage(context, state, const DiagnosticsScreen()),
      ),
      GoRoute(
        path: RoutePaths.homeAdvanced,
        pageBuilder: (BuildContext context, GoRouterState state) =>
            buildNebulaPage(context, state, const AdvancedSettingsScreen()),
      ),
    ],
  );
});
