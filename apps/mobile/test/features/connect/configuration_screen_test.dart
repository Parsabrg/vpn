import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_riverpod/misc.dart' show Override;
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/servers/server_repository.dart';
import 'package:nebula_mobile/core/storage/selection_store.dart';
import 'package:nebula_mobile/core/storage/storage_providers.dart';
import 'package:nebula_mobile/features/connect/client_summary.dart';
import 'package:nebula_mobile/features/connect/configuration_screen.dart';

import '../../support/localised_app.dart';

const String _uuid = '6f3b1c8e-1111-2222-3333-44444444d410';

const XrayClientResult _client = XrayClientResult(
  clientId: 'client-1',
  uuid: _uuid,
  serverAddress: 'de-fra-1.example.org',
  port: 8445,
  sni: 'cdn.example.net',
  transport: 'xhttp',
  transportSecurity: 'tls',
  adBlock: false,
  path: '/v1/stream',
);

Future<void> _pump(WidgetTester tester) async {
  await tester.pumpWidget(
    ProviderScope(
      overrides: <Override>[
        // The devices controller remembers the last choice, which reaches
        // SharedPreferences. Overriding the store keeps this a widget test.
        selectionStoreProvider.overrideWithValue(InMemorySelectionStore()),
      ],
      child: localisedApp(const ConfigurationScreen()),
    ),
  );
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('leads with why the screen exists', (WidgetTester tester) async {
    await _pump(tester);
    expect(find.textContaining('Registered, not tunnelling'), findsOneWidget);
  });

  testWidgets('says so plainly when there is no client to show', (
    WidgetTester tester,
  ) async {
    // Reachable if the peer was released elsewhere, or the state was rebuilt.
    // Better than an empty screen with a Copy button on it.
    await _pump(tester);
    expect(
      find.text('No client configuration on this device.'),
      findsOneWidget,
    );
    expect(find.text('Copy'), findsNothing);
  });

  testWidgets('releasing asks first', (WidgetTester tester) async {
    // Releasing is destructive and the device keeps working until the next
    // refresh, which is exactly the delay that makes an accidental tap hard
    // to connect to its consequence later.
    await _pump(tester);

    await tester.tap(find.text('Release peer'));
    await tester.pumpAndSettle();

    expect(find.text('Release peer?'), findsOneWidget);

    await tester.tap(find.text('Cancel'));
    await tester.pumpAndSettle();
    expect(find.text('Release peer?'), findsNothing);
  });

  group('truncateUuid', () {
    test('shows enough to tell two credentials apart', () {
      expect(truncateUuid(_uuid), '6f3b1c8e…d410');
    });

    test('never shows the whole credential', () {
      expect(truncateUuid(_uuid), isNot(contains(_uuid)));
      expect(truncateUuid(_uuid).length, lessThan(_uuid.length));
    });

    test('leaves a value too short to shorten alone', () {
      expect(truncateUuid('short'), 'short');
      expect(truncateUuid(''), '');
    });
  });

  group('clientSummary', () {
    test('carries the FULL uuid, not the truncation', () {
      // The point of the copy button. The screen deliberately hides most of
      // the credential; if the clipboard copied what was displayed, the
      // pasted config would simply not work.
      final String summary = clientSummary(_client);
      expect(summary, contains(_uuid));
      expect(summary, isNot(contains('…')));
    });

    test('includes every field needed to rebuild the client', () {
      final String summary = clientSummary(_client);
      expect(summary, contains('de-fra-1.example.org:8445'));
      expect(summary, contains('cdn.example.net'));
      expect(summary, contains('xhttp/tls'));
      expect(summary, contains('/v1/stream'));
    });

    test('omits path entirely when there is none', () {
      // An empty `path:` line would look like a path of "" to whoever pastes
      // it, which is a different configuration from having no path.
      const XrayClientResult noPath = XrayClientResult(
        clientId: 'c',
        uuid: _uuid,
        serverAddress: 'a',
        port: 1,
        sni: 's',
        transport: 'tcp',
        transportSecurity: 'reality',
        adBlock: false,
      );
      expect(clientSummary(noPath), isNot(contains('path:')));
    });
  });
}
