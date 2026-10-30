import 'dart:ui';

import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/servers/server_repository.dart';
import 'package:nebula_mobile/features/connect/connect_view.dart';
import 'package:nebula_mobile/features/devices/devices_state.dart';
import 'package:nebula_mobile/l10n/app_localizations.dart';

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

DevicesState _loaded({
  bool submitting = false,
  bool connected = false,
  bool tunnel = false,
  List<AvailableServer> servers = const <AvailableServer>[_frankfurt],
}) {
  return DevicesState(
    loadStatus: DevicesLoadStatus.loaded,
    servers: servers,
    xrayClient: connected ? _client : null,
    tunnelEstablished: tunnel,
    isSubmitting: submitting,
  );
}

void main() {
  group('connectViewOf', () {
    test('first load draws the skeleton, not a connection state', () {
      expect(connectViewOf(DevicesState.initial), ConnectView.loading);
    });

    test('a failed load is unreachable', () {
      expect(
        connectViewOf(const DevicesState(loadStatus: DevicesLoadStatus.failed)),
        ConnectView.unreachable,
      );
    });

    test('loaded with no permitted servers is its own state', () {
      expect(
        connectViewOf(_loaded(servers: const <AvailableServer>[])),
        ConnectView.noServers,
      );
    });

    test('idle with servers is off', () {
      expect(connectViewOf(_loaded()), ConnectView.off);
    });

    test('an in-flight request is connecting', () {
      expect(connectViewOf(_loaded(submitting: true)), ConnectView.connecting);
    });

    test('provisioned with a live tunnel is protected', () {
      expect(
        connectViewOf(_loaded(connected: true, tunnel: true)),
        ConnectView.protected,
      );
    });

    test('provisioned WITHOUT a tunnel is not protected', () {
      // The state this redesign exists to make honest. A peer registered on
      // the server with no tunnel locally is the app's most misleading
      // condition, and it is the one Android hits on every build so far.
      expect(
        connectViewOf(_loaded(connected: true, tunnel: false)),
        ConnectView.notProtected,
      );
    });

    test('a stale connection does not survive a failed reload', () {
      // Load status is checked first on purpose: claiming "Protected" over a
      // connection that can no longer be verified is worse than asking for a
      // reload.
      final DevicesState stale = DevicesState(
        loadStatus: DevicesLoadStatus.failed,
        servers: const <AvailableServer>[_frankfurt],
        xrayClient: _client,
        tunnelEstablished: true,
      );
      expect(connectViewOf(stale), ConnectView.unreachable);
    });

    test('submitting takes precedence over a previous connection', () {
      // Reconnecting to a different server: the screen should read
      // "Connecting", not keep claiming the old session is protected.
      expect(
        connectViewOf(_loaded(connected: true, tunnel: true, submitting: true)),
        ConnectView.connecting,
      );
    });
  });

  group('copy', () {
    test('only protected reports protection', () {
      for (final ConnectView view in ConnectView.values) {
        expect(
          view.isProtected,
          view == ConnectView.protected,
          reason: '$view must not claim protection',
        );
      }
    });

    test('notProtected says so in words, with no success reading', () {
      expect(
        ConnectView.notProtected.word(lookupAppText(const Locale('en'))),
        'Not protected',
      );
      expect(
        ConnectView.notProtected.ctaLabel(lookupAppText(const Locale('en'))),
        'Retry tunnel',
      );
      expect(ConnectView.notProtected.isProtected, isFalse);
    });

    test(
      'every state that shows a word has one, and both blanks are known',
      () {
        final Set<ConnectView> wordless = ConnectView.values
            .where(
              (ConnectView view) =>
                  view.word(lookupAppText(const Locale('en'))) == null,
            )
            .toSet();
        // Loading draws skeleton bars; noServers draws a three-line phrase.
        // Any other null would be an unfinished state.
        expect(wordless, <ConnectView>{
          ConnectView.loading,
          ConnectView.noServers,
        });
      },
    );

    test('every state except loading offers an action', () {
      for (final ConnectView view in ConnectView.values) {
        if (view == ConnectView.loading) {
          expect(view.ctaLabel(lookupAppText(const Locale('en'))), isNull);
        } else {
          expect(
            view.ctaLabel(lookupAppText(const Locale('en'))),
            isNotNull,
            reason: '$view has no way forward',
          );
        }
      }
    });
  });
}
