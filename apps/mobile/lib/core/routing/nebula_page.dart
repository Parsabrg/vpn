import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';

import '../theme/motion_tokens.dart';
import '../theme/reduced_motion.dart';

/// The single point every top-level route's page transition passes
/// through, so the reduced-motion preference is honored in exactly one
/// place rather than by each route redeclaring it.
CustomTransitionPage<void> buildNebulaPage(
  BuildContext context,
  GoRouterState state,
  Widget child,
) {
  final Duration duration = effectiveDuration(context, NebulaMotion.standard);
  return CustomTransitionPage<void>(
    key: state.pageKey,
    child: child,
    transitionDuration: duration,
    reverseTransitionDuration: duration,
    transitionsBuilder:
        (
          BuildContext context,
          Animation<double> animation,
          Animation<double> secondaryAnimation,
          Widget child,
        ) {
          return FadeTransition(
            opacity: CurvedAnimation(
              parent: animation,
              curve: NebulaMotion.standardCurve,
            ),
            child: child,
          );
        },
  );
}
