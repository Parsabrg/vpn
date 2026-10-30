import 'package:flutter/material.dart';

/// The Panel type scale, as a theme extension.
///
/// Flutter's `height` is a multiple of font size, where the handoff gives a
/// line height in pixels, so each style below carries the division that
/// produced it. Writing `height: 50 / 44` rather than `1.136` keeps the
/// handoff's own numbers legible here, and the compiler folds it away.
///
/// Roles are named for what they label on screen, not for Material's slots.
/// Nothing in this design is a `headlineSmall`, and mapping it onto one would
/// make every screen translate twice.
@immutable
class NebulaTypography extends ThemeExtension<NebulaTypography> {
  const NebulaTypography({
    required this.stateWord,
    required this.authTitle,
    required this.quotaFigure,
    required this.navTitle,
    required this.ctaLabel,
    required this.listTitleActive,
    required this.listTitleInactive,
    required this.inputText,
    required this.rowLabel,
    required this.rowValue,
    required this.statusLine,
    required this.topBarMeta,
    required this.wordmark,
    required this.sectionHeader,
    required this.listMeta,
    required this.tabLabel,
    required this.chipLabel,
  });

  /// Off / Connecting / Protected / Not protected.
  final TextStyle stateWord;

  /// The 40px title on every auth screen.
  final TextStyle authTitle;

  /// The quota number on the account screen.
  final TextStyle quotaFigure;

  /// Title in a screen's top bar.
  final TextStyle navTitle;

  /// The label inside a full-width call to action.
  final TextStyle ctaLabel;

  /// A list row's title, when that row is the selected or current one.
  final TextStyle listTitleActive;

  /// A list row's title otherwise.
  final TextStyle listTitleInactive;

  /// Text and placeholder inside an input.
  final TextStyle inputText;

  /// The left-hand label of a data row.
  final TextStyle rowLabel;

  /// The right-hand value of a data row. Mono, because these are numbers and
  /// identifiers and they line up down the column.
  final TextStyle rowValue;

  /// The uppercase line above the state word.
  final TextStyle statusLine;

  /// Quota and expiry, top right.
  final TextStyle topBarMeta;

  /// NEBULA, top left.
  final TextStyle wordmark;

  /// The uppercase rule above a group of rows.
  final TextStyle sectionHeader;

  /// The mono sub-line under a list row's title.
  final TextStyle listMeta;

  /// A bottom tab's label.
  final TextStyle tabLabel;

  /// The label inside a protocol chip.
  final TextStyle chipLabel;

  static const String _sans = 'Geist';
  static const String _mono = 'GeistMono';

  /// Sizes, line heights and tracking are identical across themes -- only
  /// colour changes -- so one scale serves both and is coloured at the point
  /// of use.
  static const NebulaTypography standard = NebulaTypography(
    stateWord: TextStyle(
      fontFamily: _sans,
      fontWeight: FontWeight.w500,
      fontSize: 44,
      height: 50 / 44,
      letterSpacing: -1.6,
    ),
    authTitle: TextStyle(
      fontFamily: _sans,
      fontWeight: FontWeight.w500,
      fontSize: 40,
      height: 46 / 40,
      letterSpacing: -1.4,
    ),
    quotaFigure: TextStyle(
      fontFamily: _mono,
      fontWeight: FontWeight.w400,
      fontSize: 44,
      height: 48 / 44,
      letterSpacing: -2,
    ),
    navTitle: TextStyle(
      fontFamily: _sans,
      fontWeight: FontWeight.w500,
      fontSize: 18,
      height: 24 / 18,
      letterSpacing: -0.2,
    ),
    ctaLabel: TextStyle(
      fontFamily: _sans,
      fontWeight: FontWeight.w600,
      fontSize: 16,
      height: 20 / 16,
      letterSpacing: 0.2,
    ),
    listTitleActive: TextStyle(
      fontFamily: _sans,
      fontWeight: FontWeight.w500,
      fontSize: 16,
      height: 21 / 16,
    ),
    // The handoff gives 15-16px for the inactive title. 16 keeps it on the
    // same baseline grid as the active one, which is what the mocks show.
    listTitleInactive: TextStyle(
      fontFamily: _sans,
      fontWeight: FontWeight.w400,
      fontSize: 16,
      height: 21 / 16,
    ),
    inputText: TextStyle(
      fontFamily: _sans,
      fontWeight: FontWeight.w400,
      fontSize: 15,
      height: 20 / 15,
    ),
    rowLabel: TextStyle(
      fontFamily: _sans,
      fontWeight: FontWeight.w400,
      fontSize: 13,
      height: 18 / 13,
    ),
    rowValue: TextStyle(
      fontFamily: _mono,
      fontWeight: FontWeight.w400,
      fontSize: 13,
      height: 18 / 13,
    ),
    statusLine: TextStyle(
      fontFamily: _mono,
      fontWeight: FontWeight.w400,
      fontSize: 12,
      height: 16 / 12,
      letterSpacing: 1.2,
    ),
    topBarMeta: TextStyle(
      fontFamily: _mono,
      fontWeight: FontWeight.w400,
      fontSize: 12,
      height: 16 / 12,
    ),
    wordmark: TextStyle(
      fontFamily: _mono,
      fontWeight: FontWeight.w500,
      fontSize: 13,
      height: 18 / 13,
      letterSpacing: 1.2,
    ),
    sectionHeader: TextStyle(
      fontFamily: _mono,
      fontWeight: FontWeight.w500,
      fontSize: 11,
      height: 16 / 11,
      letterSpacing: 1.2,
    ),
    listMeta: TextStyle(
      fontFamily: _mono,
      fontWeight: FontWeight.w400,
      fontSize: 11,
      height: 15 / 11,
    ),
    tabLabel: TextStyle(
      fontFamily: _sans,
      fontWeight: FontWeight.w500,
      fontSize: 12,
      height: 16 / 12,
    ),
    chipLabel: TextStyle(
      fontFamily: _mono,
      fontWeight: FontWeight.w400,
      fontSize: 12,
      height: 16 / 12,
    ),
  );

  @override
  NebulaTypography copyWith({
    TextStyle? stateWord,
    TextStyle? authTitle,
    TextStyle? quotaFigure,
    TextStyle? navTitle,
    TextStyle? ctaLabel,
    TextStyle? listTitleActive,
    TextStyle? listTitleInactive,
    TextStyle? inputText,
    TextStyle? rowLabel,
    TextStyle? rowValue,
    TextStyle? statusLine,
    TextStyle? topBarMeta,
    TextStyle? wordmark,
    TextStyle? sectionHeader,
    TextStyle? listMeta,
    TextStyle? tabLabel,
    TextStyle? chipLabel,
  }) {
    return NebulaTypography(
      stateWord: stateWord ?? this.stateWord,
      authTitle: authTitle ?? this.authTitle,
      quotaFigure: quotaFigure ?? this.quotaFigure,
      navTitle: navTitle ?? this.navTitle,
      ctaLabel: ctaLabel ?? this.ctaLabel,
      listTitleActive: listTitleActive ?? this.listTitleActive,
      listTitleInactive: listTitleInactive ?? this.listTitleInactive,
      inputText: inputText ?? this.inputText,
      rowLabel: rowLabel ?? this.rowLabel,
      rowValue: rowValue ?? this.rowValue,
      statusLine: statusLine ?? this.statusLine,
      topBarMeta: topBarMeta ?? this.topBarMeta,
      wordmark: wordmark ?? this.wordmark,
      sectionHeader: sectionHeader ?? this.sectionHeader,
      listMeta: listMeta ?? this.listMeta,
      tabLabel: tabLabel ?? this.tabLabel,
      chipLabel: chipLabel ?? this.chipLabel,
    );
  }

  @override
  NebulaTypography lerp(ThemeExtension<NebulaTypography>? other, double t) {
    if (other is! NebulaTypography) {
      return this;
    }
    return NebulaTypography(
      stateWord: TextStyle.lerp(stateWord, other.stateWord, t)!,
      authTitle: TextStyle.lerp(authTitle, other.authTitle, t)!,
      quotaFigure: TextStyle.lerp(quotaFigure, other.quotaFigure, t)!,
      navTitle: TextStyle.lerp(navTitle, other.navTitle, t)!,
      ctaLabel: TextStyle.lerp(ctaLabel, other.ctaLabel, t)!,
      listTitleActive: TextStyle.lerp(
        listTitleActive,
        other.listTitleActive,
        t,
      )!,
      listTitleInactive: TextStyle.lerp(
        listTitleInactive,
        other.listTitleInactive,
        t,
      )!,
      inputText: TextStyle.lerp(inputText, other.inputText, t)!,
      rowLabel: TextStyle.lerp(rowLabel, other.rowLabel, t)!,
      rowValue: TextStyle.lerp(rowValue, other.rowValue, t)!,
      statusLine: TextStyle.lerp(statusLine, other.statusLine, t)!,
      topBarMeta: TextStyle.lerp(topBarMeta, other.topBarMeta, t)!,
      wordmark: TextStyle.lerp(wordmark, other.wordmark, t)!,
      sectionHeader: TextStyle.lerp(sectionHeader, other.sectionHeader, t)!,
      listMeta: TextStyle.lerp(listMeta, other.listMeta, t)!,
      tabLabel: TextStyle.lerp(tabLabel, other.tabLabel, t)!,
      chipLabel: TextStyle.lerp(chipLabel, other.chipLabel, t)!,
    );
  }
}

/// Reads the Panel type scale without the `extension<...>()!` ceremony.
///
/// Falls back to [NebulaTypography.standard] for the same reason the palette
/// does: the scale is identical across themes, so the fallback is not an
/// approximation of the right answer, it is the right answer.
extension NebulaTypographyAccess on BuildContext {
  NebulaTypography get type =>
      Theme.of(this).extension<NebulaTypography>() ?? NebulaTypography.standard;
}
