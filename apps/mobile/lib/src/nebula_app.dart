import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../core/routing/app_router.dart';
import '../core/theme/nebula_theme.dart';
import '../core/theme/theme_mode_controller.dart';

class NebulaApp extends ConsumerWidget {
  const NebulaApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final ThemeMode themeMode = ref.watch(themeModeProvider);

    return MaterialApp.router(
      debugShowCheckedModeBanner: false,
      title: 'Nebula VPN',
      theme: NebulaTheme.light(),
      darkTheme: NebulaTheme.dark(),
      themeMode: themeMode,
      routerConfig: ref.watch(routerProvider),
    );
  }
}
