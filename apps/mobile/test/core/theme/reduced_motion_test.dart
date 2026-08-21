import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/theme/motion_tokens.dart';
import 'package:nebula_mobile/core/theme/reduced_motion.dart';

void main() {
  testWidgets('effectiveDuration collapses to zero when reduced motion is on', (
    WidgetTester tester,
  ) async {
    late Duration reduced;
    late Duration normal;

    await tester.pumpWidget(
      MediaQuery(
        data: const MediaQueryData(disableAnimations: true),
        child: Builder(
          builder: (BuildContext context) {
            reduced = effectiveDuration(context, NebulaMotion.standard);
            return const SizedBox.shrink();
          },
        ),
      ),
    );

    await tester.pumpWidget(
      MediaQuery(
        data: const MediaQueryData(disableAnimations: false),
        child: Builder(
          builder: (BuildContext context) {
            normal = effectiveDuration(context, NebulaMotion.standard);
            return const SizedBox.shrink();
          },
        ),
      ),
    );

    expect(reduced, Duration.zero);
    expect(normal, NebulaMotion.standard);
  });
}
