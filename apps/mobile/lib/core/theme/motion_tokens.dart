import 'package:flutter/animation.dart';

/// Named motion constants. Every transition should read its duration through
/// [effectiveDuration] in `reduced_motion.dart` rather than using these
/// directly, so reduced-motion preference has exactly one enforcement point.
abstract final class NebulaMotion {
  static const Duration standard = Duration(milliseconds: 200);
  static const Curve standardCurve = Curves.easeInOut;
}
