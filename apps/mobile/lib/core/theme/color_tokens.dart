import 'package:flutter/material.dart';

/// The Panel palette, as a theme extension.
///
/// These are exact values from the redesign handoff, not a seeded scheme.
/// `ColorScheme.fromSeed` was what the placeholder shell used, and it cannot
/// express this design: hairline, border and borderStrong are three distinct
/// greys within 0x20 of each other, and Material would collapse them into
/// whatever its tonal palette derives. Every screen reads these directly.
///
/// Lives as a [ThemeExtension] so a widget reads one object rather than
/// reaching for a global, and so light and dark cannot drift apart -- adding a
/// token to one is a compile error until the other has it too.
@immutable
class NebulaPalette extends ThemeExtension<NebulaPalette> {
  const NebulaPalette({
    required this.bg,
    required this.surface,
    required this.hairline,
    required this.border,
    required this.borderStrong,
    required this.textPrimary,
    required this.textMax,
    required this.textMuted,
    required this.blue,
    required this.blueText,
    required this.onAccent,
    required this.amber,
    required this.amberText,
    required this.amberDim,
    required this.red,
    required this.redText,
    required this.dotOff,
  });

  /// Screen background.
  final Color bg;

  /// Input fields, the config screen's single card, the disabled CTA.
  final Color surface;

  /// Row rules, tab-bar top border, progress track, skeleton blocks.
  final Color hairline;

  /// Input borders, chips, widget borders.
  final Color border;

  /// The secondary (outline) CTA border only.
  final Color borderStrong;

  /// State words, values, titles.
  final Color textPrimary;

  /// The state word when protected, and nowhere else.
  final Color textMax;

  /// Labels, meta, wordmark, inactive tabs.
  final Color textMuted;

  /// Primary CTA fill, live dot, active indicators.
  final Color blue;

  /// Accent text and icons.
  final Color blueText;

  /// Text and icons drawn on top of [blue] or [amber].
  ///
  /// One token for both because the handoff is explicit that this is never
  /// white on dark: text on blue and on amber is the background colour.
  final Color onAccent;

  /// Peer-only CTA fill, warning dot, warning icon.
  final Color amber;

  /// The "Not protected" state word.
  final Color amberText;

  /// Secondary warning meta.
  final Color amberDim;

  /// Error dot.
  final Color red;

  /// Error status line.
  final Color redText;

  /// The status dot when disconnected.
  final Color dotOff;

  /// Dark is the primary theme; every value here is specified in the handoff.
  static const NebulaPalette dark = NebulaPalette(
    bg: Color(0xFF0B0B0F),
    surface: Color(0xFF14141A),
    hairline: Color(0xFF1B1B23),
    border: Color(0xFF26262F),
    borderStrong: Color(0xFF3A3A46),
    textPrimary: Color(0xFFEDEDF2),
    textMax: Color(0xFFFFFFFF),
    textMuted: Color(0xFF8A8A96),
    blue: Color(0xFF6E8BFF),
    blueText: Color(0xFF8CA4FF),
    onAccent: Color(0xFF0B0B0F),
    amber: Color(0xFFE8B24A),
    amberText: Color(0xFFF2E3C6),
    amberDim: Color(0xFFC79A45),
    red: Color(0xFFFF6B6B),
    redText: Color(0xFFFF9494),
    dotOff: Color(0xFF8A8A96),
  );

  /// Light.
  ///
  /// The handoff specifies nine light values; the rest are marked DERIVED
  /// below. They are reasoned, not invented -- each keeps the contrast
  /// relationship its dark counterpart has -- but they have not been through
  /// design review, and the amber and red families in particular are the ones
  /// to check, since the dark values are tuned for glow on near-black and go
  /// muddy when moved onto a near-white ground.
  static const NebulaPalette light = NebulaPalette(
    bg: Color(0xFFF7F7F9),
    // DERIVED: dark lifts the field one step off the background, so light
    // drops it one step -- to white, the only step available above #F7F7F9.
    surface: Color(0xFFFFFFFF),
    hairline: Color(0xFFE3E3E8),
    border: Color(0xFFC9C9D2),
    // DERIVED: one step stronger than border, matching dark's separation.
    borderStrong: Color(0xFFA8A8B4),
    textPrimary: Color(0xFF101014),
    // DERIVED: dark's textMax is pure white against #EDEDF2, so light's is
    // pure black against #101014.
    textMax: Color(0xFF000000),
    textMuted: Color(0xFF5C5C68),
    blue: Color(0xFF2A46BE),
    // DERIVED: dark brightens accent text above the fill for contrast on a
    // dark ground; light must darken it instead.
    blueText: Color(0xFF2540A8),
    onAccent: Color(0xFFFFFFFF),
    // DERIVED: the fill stays the specified amber -- it is a fill, and the
    // handoff pins text on amber to the dark background colour either way.
    amber: Color(0xFFE8B24A),
    // DERIVED: dark's amberText is a pale cream that vanishes on white, so
    // this inverts to a dark amber with the same role.
    amberText: Color(0xFF7A5A12),
    amberDim: Color(0xFF8A6A22),
    // DERIVED: dark's reds are lightened for a dark ground; these are the
    // equivalent darkened for a light one.
    red: Color(0xFFE5484D),
    redText: Color(0xFFB42318),
    dotOff: Color(0xFFA0A0AC),
  );

  @override
  NebulaPalette copyWith({
    Color? bg,
    Color? surface,
    Color? hairline,
    Color? border,
    Color? borderStrong,
    Color? textPrimary,
    Color? textMax,
    Color? textMuted,
    Color? blue,
    Color? blueText,
    Color? onAccent,
    Color? amber,
    Color? amberText,
    Color? amberDim,
    Color? red,
    Color? redText,
    Color? dotOff,
  }) {
    return NebulaPalette(
      bg: bg ?? this.bg,
      surface: surface ?? this.surface,
      hairline: hairline ?? this.hairline,
      border: border ?? this.border,
      borderStrong: borderStrong ?? this.borderStrong,
      textPrimary: textPrimary ?? this.textPrimary,
      textMax: textMax ?? this.textMax,
      textMuted: textMuted ?? this.textMuted,
      blue: blue ?? this.blue,
      blueText: blueText ?? this.blueText,
      onAccent: onAccent ?? this.onAccent,
      amber: amber ?? this.amber,
      amberText: amberText ?? this.amberText,
      amberDim: amberDim ?? this.amberDim,
      red: red ?? this.red,
      redText: redText ?? this.redText,
      dotOff: dotOff ?? this.dotOff,
    );
  }

  @override
  NebulaPalette lerp(ThemeExtension<NebulaPalette>? other, double t) {
    if (other is! NebulaPalette) {
      return this;
    }
    return NebulaPalette(
      bg: Color.lerp(bg, other.bg, t)!,
      surface: Color.lerp(surface, other.surface, t)!,
      hairline: Color.lerp(hairline, other.hairline, t)!,
      border: Color.lerp(border, other.border, t)!,
      borderStrong: Color.lerp(borderStrong, other.borderStrong, t)!,
      textPrimary: Color.lerp(textPrimary, other.textPrimary, t)!,
      textMax: Color.lerp(textMax, other.textMax, t)!,
      textMuted: Color.lerp(textMuted, other.textMuted, t)!,
      blue: Color.lerp(blue, other.blue, t)!,
      blueText: Color.lerp(blueText, other.blueText, t)!,
      onAccent: Color.lerp(onAccent, other.onAccent, t)!,
      amber: Color.lerp(amber, other.amber, t)!,
      amberText: Color.lerp(amberText, other.amberText, t)!,
      amberDim: Color.lerp(amberDim, other.amberDim, t)!,
      red: Color.lerp(red, other.red, t)!,
      redText: Color.lerp(redText, other.redText, t)!,
      dotOff: Color.lerp(dotOff, other.dotOff, t)!,
    );
  }
}

/// Reads the Panel palette without the `extension<...>()!` ceremony at every
/// call site.
///
/// Falls back to the palette matching the ambient brightness rather than
/// throwing. A widget pumped under a bare `MaterialApp` -- which is how most
/// of this suite's widget tests are written -- would otherwise die on a null
/// check, and the fallback renders correctly rather than merely surviving. It
/// cannot mask a misconfigured app theme, because the value it falls back to
/// is the one a correct theme would have supplied.
extension NebulaPaletteAccess on BuildContext {
  NebulaPalette get palette {
    final ThemeData theme = Theme.of(this);
    return theme.extension<NebulaPalette>() ??
        (theme.brightness == Brightness.dark
            ? NebulaPalette.dark
            : NebulaPalette.light);
  }
}
