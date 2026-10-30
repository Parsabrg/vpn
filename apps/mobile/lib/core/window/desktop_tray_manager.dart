import 'dart:io' show Platform;

import 'package:flutter/foundation.dart';
import 'package:tray_manager/tray_manager.dart';

/// Manages the system tray icon and context menu on Windows.
///
/// Initialised once from [main] on desktop platforms. The tray icon stays
/// visible for the lifetime of the process; closing the window hides it
/// to the tray rather than terminating the app.
class DesktopTrayManager with TrayListener {
  DesktopTrayManager({required this.onShowWindow, required this.onExit});

  /// Called when the user double-clicks the tray icon or selects "Show".
  final VoidCallback onShowWindow;

  /// Called when the user selects "Exit" from the context menu.
  final VoidCallback onExit;

  bool _initialised = false;

  /// Sets up the tray icon and context menu. Safe to call on non-desktop
  /// platforms — it returns immediately.
  Future<void> init() async {
    if (!Platform.isWindows && !Platform.isMacOS && !Platform.isLinux) return;
    if (_initialised) return;
    _initialised = true;

    await trayManager.setIcon('assets/app_icon.ico');
    await trayManager.setToolTip('Nebula VPN');
    await _rebuildMenu();
    trayManager.addListener(this);
  }

  /// Updates the tooltip, e.g. to show connection status.
  Future<void> updateTooltip(String text) async {
    if (!_initialised) return;
    await trayManager.setToolTip(text);
  }

  Future<void> _rebuildMenu() async {
    final Menu menu = Menu(
      items: <MenuItem>[
        MenuItem(key: 'show', label: 'Show Nebula VPN'),
        MenuItem.separator(),
        MenuItem(key: 'exit', label: 'Exit'),
      ],
    );
    await trayManager.setContextMenu(menu);
  }

  @override
  void onTrayIconMouseDown() => onShowWindow();

  @override
  void onTrayIconRightMouseDown() => trayManager.popUpContextMenu();

  @override
  void onTrayMenuItemClick(MenuItem menuItem) {
    switch (menuItem.key) {
      case 'show':
        onShowWindow();
      case 'exit':
        onExit();
    }
  }

  /// Removes the tray icon. Call before the app exits.
  Future<void> dispose() async {
    if (!_initialised) return;
    trayManager.removeListener(this);
    await trayManager.destroy();
  }
}
