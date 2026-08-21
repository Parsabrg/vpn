import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../features/account/account_screen.dart';
import '../../features/account_request/account_request_screen.dart';
import '../../features/activation/activation_screen.dart';
import '../../features/auth/sign_in_screen.dart';
import '../../features/devices/devices_placeholder_screen.dart';
import '../../features/home/home_shell.dart';
import '../../features/password_reset/password_reset_confirm_screen.dart';
import '../../features/password_reset/password_reset_request_screen.dart';
import '../../features/settings/settings_screen.dart';
import '../../features/splash/splash_screen.dart';
import '../auth/auth_notifier.dart';
import '../auth/auth_state.dart';
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
  }
}

String? _redirect(Ref ref, GoRouterState state) {
  final AuthState authState = ref.read(authNotifierProvider);
  final String location = state.matchedLocation;

  switch (authState) {
    case AuthAuthenticating():
      return location == RoutePaths.splash ? null : RoutePaths.splash;
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
  final _AuthRefreshListenable refreshListenable = _AuthRefreshListenable(
    ref,
  );
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
            buildNebulaPage(
              context,
              state,
              const PasswordResetRequestScreen(),
            ),
      ),
      GoRoute(
        path: RoutePaths.passwordResetConfirm,
        pageBuilder: (BuildContext context, GoRouterState state) =>
            buildNebulaPage(
              context,
              state,
              const PasswordResetConfirmScreen(),
            ),
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
                path: RoutePaths.homeDevices,
                builder: (BuildContext context, GoRouterState state) =>
                    const DevicesPlaceholderScreen(),
              ),
            ],
          ),
          StatefulShellBranch(
            routes: <RouteBase>[
              GoRoute(
                path: RoutePaths.homeAccount,
                builder: (BuildContext context, GoRouterState state) =>
                    const AccountScreen(),
              ),
            ],
          ),
          StatefulShellBranch(
            routes: <RouteBase>[
              GoRoute(
                path: RoutePaths.homeSettings,
                builder: (BuildContext context, GoRouterState state) =>
                    const SettingsScreen(),
              ),
            ],
          ),
        ],
      ),
    ],
  );
});
