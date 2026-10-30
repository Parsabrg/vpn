/// Keeping left-to-right values intact on a right-to-left screen.
///
/// A byte count, a profile code, an address or an email is written left to
/// right in every language. Dropped into a Persian layout as-is, the
/// bidirectional algorithm reorders it: `8.9 KB` is drawn `KB 8.9`, and a
/// long code is cut from the wrong end with the ellipsis on the wrong side.
/// Found on the phone, where every such value on the Account tab did it.
library;

import 'package:flutter/widgets.dart';

// Hebrew through Arabic Extended, and the Arabic presentation forms: the
// letters that make text read right to left.
final RegExp _rightToLeftLetters = RegExp(
  '[\u0590-\u08FF\uFB1D-\uFDFF\uFE70-\uFEFF]',
);

/// Left to right for a value with no right-to-left letters in it, otherwise
/// whatever the surrounding layout says.
///
/// For a widget showing one value. A translated phrase such as "no expiry"
/// in Persian keeps the screen's direction; `vless-xhttp-tls` does not.
TextDirection? inherentDirection(String value) {
  return _rightToLeftLetters.hasMatch(value) ? null : TextDirection.ltr;
}

/// Where a value that keeps its own direction should be pushed to: the end
/// of the row in whichever direction the row runs.
///
/// Not `TextAlign.end`, which is resolved against the text's own direction:
/// a left-to-right value in a right-to-left row would then align away from
/// the end of the row it sits in.
TextAlign alignToRowEnd(BuildContext context) {
  return Directionality.of(context) == TextDirection.rtl
      ? TextAlign.left
      : TextAlign.right;
}

/// [value] fenced off inside a sentence, so it keeps its own order however
/// the words around it run.
///
/// Only in a right-to-left layout. In a left-to-right one nothing needs
/// fencing, and leaving the string untouched keeps it identical to what it
/// always was.
String embedLeftToRight(BuildContext context, String value) {
  if (Directionality.of(context) != TextDirection.rtl) {
    return value;
  }
  // LEFT-TO-RIGHT ISOLATE ... POP DIRECTIONAL ISOLATE. Invisible; they only
  // tell the layout that what is between them is a unit.
  return '\u2066$value\u2069';
}
