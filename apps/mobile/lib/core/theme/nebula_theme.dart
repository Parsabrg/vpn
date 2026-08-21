import 'package:flutter/material.dart';

import 'color_tokens.dart';

/// Material 3 theme builders shared by every screen.
abstract final class NebulaTheme {
  static ThemeData light() {
    final ColorScheme scheme = ColorScheme.fromSeed(
      seedColor: NebulaColorTokens.lightSeed,
    );
    return _themeFrom(scheme);
  }

  static ThemeData dark() {
    final ColorScheme scheme = ColorScheme.fromSeed(
      seedColor: NebulaColorTokens.darkSeed,
      brightness: Brightness.dark,
    );
    return _themeFrom(scheme);
  }

  static ThemeData _themeFrom(ColorScheme scheme) {
    return ThemeData(
      useMaterial3: true,
      colorScheme: scheme,
      inputDecorationTheme: InputDecorationTheme(
        border: OutlineInputBorder(borderRadius: BorderRadius.circular(12)),
        filled: true,
        fillColor: scheme.surfaceContainerHighest.withValues(alpha: 0.4),
      ),
      filledButtonTheme: FilledButtonThemeData(
        style: FilledButton.styleFrom(
          minimumSize: const Size.fromHeight(48),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
        ),
      ),
      appBarTheme: AppBarTheme(
        backgroundColor: scheme.surface,
        foregroundColor: scheme.onSurface,
        elevation: 0,
      ),
    );
  }
}
