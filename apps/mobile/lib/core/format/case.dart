/// Capitals as the language on screen writes them.
library;

import 'package:flutter/widgets.dart';

/// [text] in capitals, the way the language on screen makes them.
///
/// `String.toUpperCase` ignores language, and Turkish is the case where that
/// shows: its dotted and dotless i are separate letters, so a dotted i capitalises
/// to a dotted capital. Without this, "değil" became "DEĞIL" -- a different,
/// misspelt word -- on every status line and section header.
///
/// Scripts without case (Persian, Arabic, Chinese) come back unchanged.
String upperCaseFor(BuildContext context, String text) {
  if (Localizations.maybeLocaleOf(context)?.languageCode == 'tr') {
    return text.replaceAll('i', '\u0130').toUpperCase();
  }
  return text.toUpperCase();
}
