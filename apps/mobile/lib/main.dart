import 'dart:async';
import 'dart:io' show Platform;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show PlatformException;
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_riverpod/misc.dart' show Override;
import 'package:shared_preferences/shared_preferences.dart';
import 'package:window_manager/window_manager.dart';

import 'core/auth/auth_notifier.dart';
import 'core/free/free_mode.dart';
import 'core/licenses/bundled_licenses.dart';
import 'core/pairing/pairing.dart';
import 'core/pairing/pairing_providers.dart';
import 'core/pairing/pairing_store.dart';
import 'core/storage/storage_providers.dart';
import 'core/tunnel/windows_temp_sweep.dart';
import 'core/window/desktop_tray_manager.dart';
import 'core/window/login_item.dart';
import 'src/nebula_app.dart';

DesktopTrayManager? _trayManager;

Future<void> main(List<String> arguments) async {
  WidgetsFlutterBinding.ensureInitialized();
  registerBundledLicenses();

  if (Platform.isWindows) {
    await windowManager.ensureInitialized();

    const WindowOptions windowOptions = WindowOptions(
      size: Size(420, 720),
      minimumSize: Size(380, 640),
      center: true,
      title: 'Nebula VPN',
      // Keeps the standard title bar with minimize/maximize/close buttons,
      // which is what Windows users expect from a utility app.
    );

    await windowManager.waitUntilReadyToShow(windowOptions, () async {
      // Started at sign-in: stay in the tray until opened from there.
      if (arguments.contains(startHiddenArgument)) {
        return;
      }
      await windowManager.show();
      await windowManager.focus();
    });

    // Close button hides to tray instead of killing the app, so the VPN
    // connection stays up when the user dismisses the window.
    await windowManager.setPreventClose(true);

    _trayManager = DesktopTrayManager(
      onShowWindow: () async {
        await windowManager.show();
        await windowManager.focus();
      },
      onExit: () async {
        await _trayManager?.dispose();
        await windowManager.setPreventClose(false);
        await windowManager.close();
      },
    );
    await _trayManager!.init();

    windowManager.addListener(_NebulaWindowListener());
  }
  if (Platform.isWindows || Platform.isLinux) {
    // Not awaited: nothing on screen waits for it.
    unawaited(sweepStaleTunnelFolders());
  }

  final SharedPreferences preferences = await SharedPreferences.getInstance();
  // Before the first frame, so the first request already goes to the paired
  // deployment -- or, unpaired, nowhere.
  final Pairing? pairing;
  try {
    pairing = await FlutterSecurePairingStore().read();
  } on PlatformException catch (error) {
    // Linux keeps secrets in the desktop's Secret Service; a desktop without
    // one (a bare window manager, some minimal installs) used to crash here.
    if (!Platform.isLinux) rethrow;
    runApp(_KeyringMissingApp(detail: error.message ?? error.code));
    return;
  }

  final ProviderContainer container = ProviderContainer(
    overrides: <Override>[
      sharedPreferencesProvider.overrideWithValue(preferences),
      storedPairingProvider.overrideWithValue(pairing),
      storedFreeModeProvider.overrideWithValue(
        preferences.getBool(freeModeKey) ?? false,
      ),
    ],
    // Riverpod 3 retries a failed provider on its own, with backoff, up to ten
    // times. Every load here already has its own failure state and a Try
    // again the person presses, and a silent retry loop would both hide the
    // failure behind a spinner and send the same refused request to the API
    // over and over. Off, which is the behaviour the app was built against.
    retry: (int retryCount, Object error) => null,
  );

  // Deliberately not awaited: the app renders immediately (showing the
  // splash screen, since AuthNotifier.build()'s initial state is
  // AuthAuthenticating) while bootstrap runs in the background. Awaiting it
  // here would block the first frame until the refresh call resolves,
  // defeating the point of having a splash screen at all. Called once, here
  // -- not from any widget's build/initState -- so there is exactly one
  // bootstrap attempt per process start, independent of widget rebuilds.
  unawaited(container.read(authNotifierProvider.notifier).bootstrap());

  runApp(
    UncontrolledProviderScope(container: container, child: const NebulaApp()),
  );
}

/// Intercepts the native close button so the window hides to the system tray
/// instead of terminating the process. The VPN tunnel survives.
class _NebulaWindowListener extends WindowListener {
  @override
  void onWindowClose() async {
    // Hide rather than close so the tunnel keeps running.
    await windowManager.hide();
  }
}

/// Shown instead of the app when Linux has nowhere safe to keep the pairing.
class _KeyringMissingApp extends StatelessWidget {
  const _KeyringMissingApp({required this.detail});

  final String detail;

  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'Nebula VPN',
    home: Scaffold(
      body: Padding(
        padding: const EdgeInsets.all(24),
        child: Center(
          child: SelectableText(
            'Nebula VPN needs a keyring to store its sign-in safely.\n\n'
            'Install and start GNOME Keyring or KWallet (the package is '
            'usually "gnome-keyring"), sign out and back in, then open '
            'Nebula VPN again.\n\n$detail',
          ),
        ),
      ),
    ),
  );
}
