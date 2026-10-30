import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/auth/auth_notifier.dart';
import '../../core/auth/auth_state.dart';
import '../../core/free/free_mode.dart';
import '../../core/storage/storage_providers.dart';
import '../../core/theme/color_tokens.dart';
import '../../core/theme/type_scale.dart';
import '../../core/wireguard/tunnel_controller.dart';
import '../../l10n/app_localizations.dart';
import '../devices/devices_controller.dart';

/// The authenticated area's shell: three tabs over a hairline.
///
/// Connect, Devices, Account. Settings is deliberately not a tab -- it is
/// pushed from Account with a back arrow, because it is somewhere you go to
/// change something and then leave, not one of the three places the app is
/// about.
///
/// Each branch keeps its own navigation stack via [StatefulNavigationShell],
/// so switching tabs does not lose a tab's scroll position or its pushed
/// screens.
///
/// Also where the tunnel notification's Disconnect button is answered: the
/// tap opens the app on whichever tab was last showing, so it is handled
/// here rather than by one of them.
class HomeShell extends ConsumerStatefulWidget {
  const HomeShell({required this.navigationShell, super.key});

  final StatefulNavigationShell navigationShell;

  @override
  ConsumerState<HomeShell> createState() => _HomeShellState();
}

class _HomeShellState extends ConsumerState<HomeShell> {
  StreamSubscription<void>? _disconnectRequests;

  @override
  void initState() {
    super.initState();
    _disconnectRequests = ref
        .read(tunnelControllerProvider)
        .disconnectRequests()
        .listen((_) {
          ref
              .read(devicesControllerProvider.notifier)
              .disconnectFromNotification(
                ref.read(deviceIdStoreProvider).read(),
              );
        });
  }

  @override
  void dispose() {
    _disconnectRequests?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final StatefulNavigationShell navigationShell = widget.navigationShell;
    final NebulaPalette palette = context.palette;

    // The session ended without this device asking: revoked by an admin,
    // or the account disabled. The router leaves for sign-in; the tunnel
    // must not stay up behind it, carrying nothing.
    final bool free = ref.watch(freeModeProvider);
    ref.listen<AuthState>(authNotifierProvider, (
      AuthState? previous,
      AuthState next,
    ) {
      // With no server there is no session to lose.
      if (free) {
        return;
      }
      if (next is AuthSessionExpired || next is AuthUnauthenticated) {
        unawaited(
          ref.read(devicesControllerProvider.notifier).endAfterSessionLost(),
        );
      }
      // The server answers again: a tunnel raised from a saved credential
      // while it could not be reached is replaced by a fresh one.
      if (previous is AuthUnreachable && next is AuthAuthenticated) {
        unawaited(
          ref
              .read(devicesControllerProvider.notifier)
              .refreshAfterOffline(ref.read(deviceIdStoreProvider).read()),
        );
      }
    });

    return Scaffold(
      backgroundColor: palette.bg,
      body: navigationShell,
      bottomNavigationBar: _PanelTabBar(
        free: free,
        currentIndex: navigationShell.currentIndex,
        onSelected: (int index) => navigationShell.goBranch(
          index,
          // Tapping the tab you are already on returns it to its root, which
          // is the standard escape from a stack you pushed too deep.
          initialLocation: index == navigationShell.currentIndex,
        ),
      ),
    );
  }
}

/// 60px tall, one hairline on top, three equal items.
///
/// Not Material's `NavigationBar`: that draws a pill indicator behind the
/// selected icon and reserves a much taller minimum height, neither of which
/// this design has room for.
class _PanelTabBar extends StatelessWidget {
  const _PanelTabBar({
    required this.free,
    required this.currentIndex,
    required this.onSelected,
  });

  /// No server: no devices to list, and the third tab is the relays.
  final bool free;
  final int currentIndex;
  final ValueChanged<int> onSelected;

  // Outline and filled icon for each tab, in branch order. The labels are
  // read in build, because they depend on the language being shown.
  static const List<(IconData, IconData)> _icons = <(IconData, IconData)>[
    (Icons.shield_outlined, Icons.shield),
    (Icons.devices_outlined, Icons.devices),
    (Icons.person_outline, Icons.person),
  ];

  @override
  Widget build(BuildContext context) {
    final NebulaPalette palette = context.palette;
    final NebulaTypography type = context.type;
    final AppText text = AppText.of(context);
    final List<String> labels = <String>[
      text.tabConnect,
      text.tabDevices,
      free ? text.freeTab : text.tabAccount,
    ];

    // The system inset goes below the 60px, not inside it. With the inset
    // inside a fixed-height box, a phone on 3-button navigation (a ~48px
    // inset) left the tabs about 12px and cut the icons in half; gesture
    // navigation's small inset hid that on the phone this was built on.
    return DecoratedBox(
      decoration: BoxDecoration(
        color: palette.bg,
        border: Border(top: BorderSide(color: palette.hairline)),
      ),
      child: SafeArea(
        top: false,
        child: SizedBox(
          height: 60,
          child: Row(
            children: <Widget>[
              for (int index = 0; index < _icons.length; index++)
                if (!(free && index == 1))
                  Expanded(
                    child: _Tab(
                      // The active tab is the filled icon, per the design's
                      // "FILL 0 except the active tab icon".
                      icon: index == currentIndex
                          ? _icons[index].$2
                          : _icons[index].$1,
                      label: labels[index],
                      selected: index == currentIndex,
                      onTap: () => onSelected(index),
                      palette: palette,
                      type: type,
                    ),
                  ),
            ],
          ),
        ),
      ),
    );
  }
}

class _Tab extends StatelessWidget {
  const _Tab({
    required this.icon,
    required this.label,
    required this.selected,
    required this.onTap,
    required this.palette,
    required this.type,
  });

  final IconData icon;
  final String label;
  final bool selected;
  final VoidCallback onTap;
  final NebulaPalette palette;
  final NebulaTypography type;

  @override
  Widget build(BuildContext context) {
    final Color color = selected ? palette.blue : palette.textMuted;

    return Semantics(
      button: true,
      selected: selected,
      label: label,
      child: InkWell(
        onTap: onTap,
        child: Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            Icon(icon, size: 20, color: color),
            const SizedBox(width: 8),
            // Shrinks to fit rather than truncating. A third of the width is
            // not enough for every language's word beside an icon -- Russian
            // "Подключение" was cut to "Подключен…" on a real phone -- and a
            // slightly smaller label reads far better than half of one.
            Flexible(
              child: FittedBox(
                fit: BoxFit.scaleDown,
                child: Text(
                  label,
                  maxLines: 1,
                  style: type.tabLabel.copyWith(color: color),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
