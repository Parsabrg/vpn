/// Dates as the screens show them, in the language on screen.
library;

import 'package:flutter/widgets.dart';
import 'package:intl/intl.dart';

/// `2 Sep` -- for a list, where the year is almost always this one.
String formatShortDate(BuildContext context, DateTime time) {
  return DateFormat('d MMM', _locale(context)).format(time.toLocal());
}

/// `2 Sep 2026` -- for a deadline, where the year matters.
String formatLongDate(BuildContext context, DateTime time) {
  return DateFormat('d MMM y', _locale(context)).format(time.toLocal());
}

/// Month names and digits come from the locale rather than a hardcoded
/// English list, so a Persian screen does not print "Sep" mid-sentence.
///
/// Still the Gregorian calendar in every language. Most people reading
/// Persian date things by the Solar Hijri calendar, which intl does not
/// provide; showing it is a separate change with its own dependency.
String _locale(BuildContext context) =>
    Localizations.localeOf(context).languageCode;
