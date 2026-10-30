/// The screen somebody opens when the app says connected and nothing loads.
///
/// Every other signal reports the tunnel as fine in exactly that case, so
/// what this screen owes is to distinguish three states that look identical
/// if handled carelessly: still loading, healthy and quiet, and unable to
/// read the log at all. "Nothing here" for all three is the failure.
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_riverpod/misc.dart' show Override;
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/xray/xray_tunnel_controller.dart';
import 'package:nebula_mobile/features/settings/connection_log_screen.dart';

import '../../support/localised_app.dart';
import '../devices/fake_xray_tunnel_controller.dart';

Future<FakeXrayTunnelController> _pump(
  WidgetTester tester, {
  List<String> lines = const <String>[],
  Object? error,
}) async {
  final FakeXrayTunnelController tunnel = FakeXrayTunnelController()
    ..logLines = lines
    ..logsError = error;
  await tester.pumpWidget(
    ProviderScope(
      overrides: <Override>[
        xrayTunnelControllerProvider.overrideWithValue(tunnel),
      ],
      child: localisedApp(const ConnectionLogScreen()),
    ),
  );
  await tester.pumpAndSettle();
  return tunnel;
}

void main() {
  testWidgets('a quiet log says so rather than looking broken', (
    WidgetTester tester,
  ) async {
    // The healthy state. A blank screen here reads as the feature being
    // broken, which is the last thing somebody already debugging a
    // connection needs to start wondering about.
    await _pump(tester);

    expect(find.textContaining('Nothing to report'), findsOneWidget);
    expect(find.textContaining('normal state'), findsOneWidget);
  });

  testWidgets('lines are shown as the core wrote them', (
    WidgetTester tester,
  ) async {
    await _pump(
      tester,
      lines: <String>[
        'failed to handle mux client connection',
        'transport/internet/websocket: failed to dial',
      ],
    );

    expect(
      find.textContaining('failed to handle mux client connection'),
      findsOneWidget,
    );
    expect(find.textContaining('transport/internet/websocket'), findsOneWidget);
  });

  testWidgets('a log that cannot be read is not shown as an empty one', (
    WidgetTester tester,
  ) async {
    // These are different facts. Reporting a failure to read as "nothing to
    // report" would tell somebody their tunnel is healthy on the strength of
    // a call that never succeeded.
    await _pump(tester, error: StateError('no core on this platform'));

    expect(find.textContaining('could not be read'), findsOneWidget);
    expect(find.textContaining('Nothing to report'), findsNothing);
  });

  testWidgets('clearing empties the log and leaves the screen usable', (
    WidgetTester tester,
  ) async {
    final FakeXrayTunnelController tunnel = await _pump(
      tester,
      lines: <String>['failed to dial'],
    );

    await tester.tap(find.byTooltip('Clear'));
    await tester.pumpAndSettle();

    expect(tunnel.clearLogCalls, 1);
    expect(find.textContaining('Nothing to report'), findsOneWidget);
  });

  testWidgets('there is nothing to clear or copy on an empty log', (
    WidgetTester tester,
  ) async {
    // Controls that do nothing invite a tap that appears to fail.
    await _pump(tester);

    expect(find.byTooltip('Clear'), findsNothing);
    expect(find.byTooltip('Copy'), findsNothing);
    expect(find.byTooltip('Refresh'), findsOneWidget);
  });

  testWidgets('refreshing re-reads rather than reusing what was shown', (
    WidgetTester tester,
  ) async {
    final FakeXrayTunnelController tunnel = await _pump(tester);

    tunnel.logLines = <String>['connection refused'];
    await tester.tap(find.byTooltip('Refresh'));
    await tester.pumpAndSettle();

    expect(find.textContaining('connection refused'), findsOneWidget);
  });

  testWidgets('the log is selectable so one line can be taken out of it', (
    WidgetTester tester,
  ) async {
    // Somebody reporting a problem needs the one line that matters, not a
    // screenshot of the whole buffer.
    await _pump(tester, lines: <String>['failed to dial']);

    expect(find.byType(SelectableText), findsOneWidget);
  });
}
