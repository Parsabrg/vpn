import 'dart:async';

import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'core/auth/auth_notifier.dart';
import 'core/storage/storage_providers.dart';
import 'src/nebula_app.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  final SharedPreferences preferences = await SharedPreferences.getInstance();

  final ProviderContainer container = ProviderContainer(
    overrides: <Override>[
      sharedPreferencesProvider.overrideWithValue(preferences),
    ],
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
