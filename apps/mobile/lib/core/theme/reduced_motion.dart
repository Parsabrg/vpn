import 'package:flutter/widgets.dart';

/// The single point every page transition and animated widget routes its
/// duration through. Collapses to zero when the platform's reduced-motion
/// accessibility preference is on, so no individual widget has to branch on
/// [MediaQuery] itself.
Duration effectiveDuration(BuildContext context, Duration base) {
  return MediaQuery.disableAnimationsOf(context) ? Duration.zero : base;
}
