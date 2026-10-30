import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/servers/server_repository.dart';
import 'package:nebula_mobile/core/theme/color_tokens.dart';
import 'package:nebula_mobile/core/tunnel/tunnel_traffic.dart';
import 'package:nebula_mobile/features/connect/connect_screen.dart';
import 'package:nebula_mobile/features/connect/connect_view.dart';
import 'package:nebula_mobile/features/devices/devices_state.dart';

import '../../support/localised_app.dart';

/// Drives the screen straight from a [DevicesState] rather than through the
/// controller.
///
/// The controller's own behaviour is covered by `devices_controller_test`;
/// what these tests are for is the mapping from a state to what a person sees,
/// and routing every case through a fake repository would make that mapping
/// harder to read, not better tested.
Future<void> _pump(
  WidgetTester tester,
  ConnectView view,
  DevicesState state, {
  TunnelTraffic? traffic,
}) {
  return tester.pumpWidget(
    ProviderScope(
      child: localisedApp(
        Scaffold(
          body: ListView(
            children: <Widget>[
              ConnectStateBlock(view: view, state: state, traffic: traffic),
              ConnectMessages(state: state),
            ],
          ),
        ),
      ),
    ),
  );
}

const AvailableServer _frankfurt = AvailableServer(
  code: 'de-fra-1',
  displayName: 'Frankfurt',
  publicHost: 'fra.example.org',
  profiles: <AvailableProfile>[],
);

const XrayClientResult _client = XrayClientResult(
  clientId: 'client-1',
  uuid: '6f3b1c8e-0000-0000-0000-00000000d410',
  serverAddress: 'fra.example.org',
  port: 443,
  sni: 'fra.example.org',
  transport: 'xhttp',
  transportSecurity: 'tls',
  adBlock: false,
);

DevicesState _state({
  bool connected = false,
  bool tunnel = false,
  String? actionError,
}) {
  return DevicesState(
    loadStatus: DevicesLoadStatus.loaded,
    servers: const <AvailableServer>[_frankfurt],
    selectedServerCode: 'de-fra-1',
    xrayClient: connected ? _client : null,
    tunnelEstablished: tunnel,
    actionErrorMessage: actionError,
  );
}

/// Finds the colour actually painted on a piece of text.
Color _colorOf(WidgetTester tester, String text) {
  return tester.widget<Text>(find.text(text)).style!.color!;
}

void main() {
  group('live traffic', _trafficTests);

  group('a failed attempt', () {
    // Found on a real phone, against the real server. The account's data
    // allowance was spent, the API answered 402, the controller recorded the
    // message it is meant to -- and the screen drew nothing, so Connect
    // looked like a button that did not work. Pressing it again was then the
    // only sensible thing to try, and it failed the same silent way.
    const String quotaMessage =
        'Data limit reached. Ask your administrator for more data.';

    testWidgets('says why, instead of looking like a dead button', (
      WidgetTester tester,
    ) async {
      await _pump(tester, ConnectView.off, _state(actionError: quotaMessage));

      expect(find.text(quotaMessage), findsOneWidget);
    });

    testWidgets('nothing is drawn when the last attempt did not fail', (
      WidgetTester tester,
    ) async {
      // A permanent empty box where an error would go reads as something
      // being wrong on a screen where nothing is.
      await _pump(tester, ConnectView.off, _state());

      expect(find.byIcon(Icons.error_outline), findsNothing);
    });

    testWidgets('the whole sentence survives, including the part that helps', (
      WidgetTester tester,
    ) async {
      // The copy ends in the one thing that actually fixes it. A row that
      // ellipsized would drop exactly that half -- the same failure the
      // traffic rows hit on a real phone.
      await _pump(tester, ConnectView.off, _state(actionError: quotaMessage));

      final Text rendered = tester.widget<Text>(find.text(quotaMessage));
      expect(rendered.overflow, isNot(TextOverflow.ellipsis));
      expect(rendered.maxLines, isNull);
      expect(tester.takeException(), isNull);
    });

    testWidgets('a failure while connected is still reported', (
      WidgetTester tester,
    ) async {
      // Disconnect can fail too, and the screen it fails on is this one.
      await _pump(
        tester,
        ConnectView.protected,
        _state(connected: true, tunnel: true, actionError: quotaMessage),
      );

      expect(find.text(quotaMessage), findsOneWidget);
    });
  });

  testWidgets('off shows the word and both pickable rows', (
    WidgetTester tester,
  ) async {
    await _pump(tester, ConnectView.off, _state());
    expect(find.text('Off'), findsOneWidget);
    expect(find.text('DISCONNECTED'), findsOneWidget);
    expect(find.text('Server'), findsOneWidget);
    expect(find.text('Protocol'), findsOneWidget);
  });

  testWidgets('protected uses textMax, the brightest token', (
    WidgetTester tester,
  ) async {
    await _pump(
      tester,
      ConnectView.protected,
      _state(connected: true, tunnel: true),
    );
    expect(find.text('Protected'), findsOneWidget);
    expect(_colorOf(tester, 'Protected'), NebulaPalette.dark.textMax);
  });

  group('not protected', () {
    // The state the redesign exists for. Each of these is a separate way the
    // screen could accidentally reassure someone who is not protected.

    testWidgets('says it in words', (WidgetTester tester) async {
      await _pump(tester, ConnectView.notProtected, _state(connected: true));
      expect(find.text('Not protected'), findsOneWidget);
      expect(find.text('Protected'), findsNothing);
    });

    testWidgets('offers the protocol, so a blocked one can be swapped', (
      WidgetTester tester,
    ) async {
      await _pump(tester, ConnectView.notProtected, _state(connected: true));
      expect(find.text('Protocol'), findsOneWidget);
    });

    testWidgets('offers the server, as "try another server" says', (
      WidgetTester tester,
    ) async {
      await _pump(tester, ConnectView.notProtected, _state(connected: true));
      // Amber like the protocol row: a value that opens the server list.
      expect(_colorOf(tester, 'Frankfurt'), NebulaPalette.dark.amberText);
    });

    testWidgets('free mode does not speak of peers or registration', (
      WidgetTester tester,
    ) async {
      await tester.pumpWidget(
        ProviderScope(
          child: localisedApp(
            Scaffold(
              body: ListView(
                children: <Widget>[
                  ConnectStateBlock(
                    view: ConnectView.notProtected,
                    state: _state(connected: true),
                    freeMode: true,
                  ),
                ],
              ),
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();
      expect(find.text('NO TUNNEL'), findsOneWidget);
      expect(find.textContaining('PEER'), findsNothing);
      expect(find.text('Registered on'), findsNothing);
    });

    testWidgets('the status line names the cause', (WidgetTester tester) async {
      await _pump(tester, ConnectView.notProtected, _state(connected: true));
      expect(find.text('PEER ONLY · NO TUNNEL'), findsOneWidget);
    });

    testWidgets('the word is amber, never the success colours', (
      WidgetTester tester,
    ) async {
      await _pump(tester, ConnectView.notProtected, _state(connected: true));
      final Color color = _colorOf(tester, 'Not protected');
      expect(color, NebulaPalette.dark.amberText);
      expect(color, isNot(NebulaPalette.dark.textMax));
      expect(color, isNot(NebulaPalette.dark.blue));
      expect(color, isNot(NebulaPalette.dark.blueText));
    });

    testWidgets('no blue appears anywhere on the screen', (
      WidgetTester tester,
    ) async {
      // Blue is the app's success and activity colour. A single blue accent
      // in this state -- an unthinking chevron, a default link colour -- is
      // enough to make the screen read as working.
      await _pump(tester, ConnectView.notProtected, _state(connected: true));

      final Iterable<Text> texts = tester.widgetList<Text>(find.byType(Text));
      for (final Text text in texts) {
        final Color? color = text.style?.color;
        expect(
          color,
          isNot(NebulaPalette.dark.blue),
          reason: '"${text.data}" is blue',
        );
        expect(
          color,
          isNot(NebulaPalette.dark.blueText),
          reason: '"${text.data}" is blue',
        );
      }
    });
  });

  testWidgets('unreachable explains itself rather than showing rows', (
    WidgetTester tester,
  ) async {
    await _pump(
      tester,
      ConnectView.unreachable,
      const DevicesState(loadStatus: DevicesLoadStatus.failed),
    );
    expect(find.text('Unreachable'), findsOneWidget);
    expect(find.text('NO CONNECTION'), findsOneWidget);
    expect(find.text('check your network'), findsOneWidget);
    expect(find.text('Server'), findsNothing);
  });

  testWidgets('no servers reads as a state, not an error', (
    WidgetTester tester,
  ) async {
    await _pump(
      tester,
      ConnectView.noServers,
      const DevicesState(loadStatus: DevicesLoadStatus.loaded),
    );
    expect(find.textContaining('Nothing'), findsOneWidget);
    expect(find.text('0 SERVERS'), findsOneWidget);
  });

  testWidgets('loading is a skeleton, never a spinner', (
    WidgetTester tester,
  ) async {
    // The handoff is explicit about this, and the screen it replaces used a
    // CircularProgressIndicator.
    await _pump(tester, ConnectView.loading, DevicesState.initial);
    await tester.pump(const Duration(milliseconds: 100));
    expect(find.byType(CircularProgressIndicator), findsNothing);
    expect(find.text('Off'), findsNothing);
  });
}

/// The live traffic figures.
///
/// Both hazards here are silent. A swapped direction shows believable numbers
/// that are exactly backwards -- the client's download named as its upload --
/// and no amount of looking at the screen reveals it. And a missing reading
/// drawn as zero is indistinguishable from a tunnel carrying nothing, on a
/// screen that has just said "Protected".
void _trafficTests() {
  const int kib = 1024;
  const int mib = kib * 1024;

  testWidgets('shows what the tunnel has actually carried', (
    WidgetTester tester,
  ) async {
    await _pump(
      tester,
      ConnectView.protected,
      _state(connected: true, tunnel: true),
      traffic: const TunnelTraffic(
        rxBytes: 340 * mib,
        txBytes: 12 * mib,
        elapsed: Duration(minutes: 7, seconds: 4),
      ),
    );

    // Down is what arrived on this device, and is the larger of the two for
    // anyone browsing. Reversed, this reads as a device that uploaded 340 MB.
    // Two separate rows, so neither figure can crowd the other out of
    // the one it shares -- which truncated the upload away on a phone.
    expect(find.text('Downloaded'), findsOneWidget);
    expect(find.text('340 MB'), findsOneWidget);
    expect(find.text('Uploaded'), findsOneWidget);
    expect(find.text('12 MB'), findsOneWidget);
    expect(find.text('7:04'), findsOneWidget);
  });

  testWidgets('no reading yet is an em dash, not a zero', (
    WidgetTester tester,
  ) async {
    // The moment after a tunnel comes up and before its first report.
    await _pump(
      tester,
      ConnectView.protected,
      _state(connected: true, tunnel: true),
    );

    expect(find.text('Downloaded'), findsOneWidget);
    expect(find.text('Uploaded'), findsOneWidget);
    expect(find.text('—'), findsWidgets);
    expect(find.textContaining('0 B'), findsNothing);
  });

  testWidgets('a reading of zero is shown as zero, not as no reading', (
    WidgetTester tester,
  ) async {
    // A tunnel that is up and has carried nothing is a real answer, and a
    // different one from having no reading at all.
    await _pump(
      tester,
      ConnectView.protected,
      _state(connected: true, tunnel: true),
      traffic: const TunnelTraffic(rxBytes: 0, txBytes: 0),
    );

    expect(find.text('0 B'), findsNWidgets(2));
  });

  testWidgets('an unknown session length is an em dash, not a clock at zero', (
    WidgetTester tester,
  ) async {
    // WireGuard counts bytes, not time. A clock that started when the screen
    // opened would be a plausible number that is simply wrong.
    await _pump(
      tester,
      ConnectView.protected,
      _state(connected: true, tunnel: true),
      traffic: const TunnelTraffic(rxBytes: 5 * mib, txBytes: mib),
    );

    expect(find.text('Session'), findsOneWidget);
    expect(find.text('0:00'), findsNothing);
  });

  testWidgets('traffic is not offered on a screen with no tunnel', (
    WidgetTester tester,
  ) async {
    // notProtected means provisioned with nothing running. A byte counter
    // there would be the single most misleading thing this screen can draw.
    await _pump(tester, ConnectView.notProtected, _state(connected: true));

    expect(find.text('Downloaded'), findsNothing);
    expect(find.text('Uploaded'), findsNothing);
    expect(find.text('Session'), findsNothing);
  });

  testWidgets('sanctions-only mode does not claim the device is protected', (
    WidgetTester tester,
  ) async {
    // Most traffic is leaving directly in this mode, and the largest word on
    // the screen is the last place to suggest otherwise.
    await _pump(
      tester,
      ConnectView.protected,
      const DevicesState(
        loadStatus: DevicesLoadStatus.loaded,
        servers: <AvailableServer>[_frankfurt],
        selectedServerCode: 'de-fra-1',
        xrayClient: _client,
        tunnelEstablished: true,
        sanctionsOnly: true,
      ),
    );

    expect(find.text('Protected'), findsNothing);
    expect(find.text('On'), findsOneWidget);
    expect(find.textContaining('SANCTIONED SERVICES ONLY'), findsOneWidget);
  });
}
