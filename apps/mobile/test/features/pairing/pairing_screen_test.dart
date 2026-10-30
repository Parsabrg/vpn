import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_riverpod/misc.dart' show Override;
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:nebula_mobile/core/pairing/pairing.dart';
import 'package:nebula_mobile/core/pairing/pairing_providers.dart';
import 'package:nebula_mobile/core/pairing/pairing_store.dart';
import 'package:nebula_mobile/core/routing/route_paths.dart';
import 'package:nebula_mobile/core/storage/secure_token_store.dart';
import 'package:nebula_mobile/core/storage/storage_providers.dart';
import 'package:nebula_mobile/core/theme/nebula_theme.dart';
import 'package:nebula_mobile/features/pairing/pairing_screen.dart';
import 'package:nebula_mobile/features/pairing/qr_scan.dart';
import 'package:nebula_mobile/l10n/app_localizations.dart';
import 'package:shared_preferences/shared_preferences.dart';

const String _deployment = '7d3c1f2e-0b5a-4c9d-8e61-2f4a9b0c1d2e';

/// Not a real certificate: the pin is the hash of whatever the PEM carries,
/// which is all these tests need.
const String _caPem =
    '-----BEGIN CERTIFICATE-----\nTmVidWxhIHRlc3QgQ0E=\n-----END CERTIFICATE-----';

Map<String, Object?> _record() => <String, Object?>{
  'version': 1,
  'deployment_id': _deployment,
  'deployment_name': 'Home',
  'api_url': 'https://vpn.example.org',
  'ca_certificate': _caPem,
  'ca_sha256': null,
  'profiles': <Object?>['wireguard-native'],
};

class _Harness {
  _Harness(this.preferences);

  final SharedPreferences preferences;
  final InMemoryPairingStore store = InMemoryPairingStore();
  final List<Uri> fetched = <Uri>[];
  String? scanResult;
  int scans = 0;

  List<Override> get overrides => <Override>[
    sharedPreferencesProvider.overrideWithValue(preferences),
    pairingStoreProvider.overrideWithValue(store),
    secureTokenStoreProvider.overrideWithValue(InMemorySecureTokenStore()),
    pairingProvider.overrideWith(_Unpaired.new),
    pairingClientProvider.overrideWithValue(
      PairingClient(
        fetch: (Uri origin, {String? trustOnly, bool unverified = false}) {
          fetched.add(origin);
          return Future<Map<String, Object?>>.value(_record());
        },
      ),
    ),
    qrScanProvider.overrideWithValue((BuildContext _) async {
      scans++;
      return scanResult;
    }),
  ];
}

class _Unpaired extends PairingNotifier {
  @override
  Pairing? build() => null;
}

Future<void> _pump(WidgetTester tester, _Harness harness) {
  final GoRouter router = GoRouter(
    routes: <RouteBase>[
      GoRoute(path: '/', builder: (_, _) => const PairingScreen()),
      GoRoute(
        path: RoutePaths.signIn,
        builder: (_, _) => const Scaffold(body: Text('sign-in screen')),
      ),
    ],
  );
  addTearDown(router.dispose);
  return tester.pumpWidget(
    ProviderScope(
      overrides: harness.overrides,
      child: MaterialApp.router(
        theme: NebulaTheme.dark(),
        locale: const Locale('en'),
        supportedLocales: AppText.supportedLocales,
        localizationsDelegates: const <LocalizationsDelegate<Object>>[
          AppText.delegate,
          GlobalMaterialLocalizations.delegate,
          GlobalWidgetsLocalizations.delegate,
          GlobalCupertinoLocalizations.delegate,
        ],
        routerConfig: router,
      ),
    ),
  );
}

void main() {
  late String pin;
  late SharedPreferences preferences;

  setUpAll(() async {
    pin = await caFingerprint(_caPem);
  });

  setUp(() async {
    SharedPreferences.setMockInitialValues(<String, Object>{});
    preferences = await SharedPreferences.getInstance();
  });

  group('on Android', () {
    testWidgets(
      'a scanned code pairs exactly as a pasted link does',
      (WidgetTester tester) async {
        final _Harness harness = _Harness(preferences)
          ..scanResult =
              'https://vpn.example.org/pair#v=1&d=$_deployment&ca=$pin';
        await _pump(tester, harness);

        await tester.tap(find.text('Scan QR code'));
        await tester.pumpAndSettle();

        expect(harness.scans, 1);
        expect(harness.fetched.first, Uri.parse('https://vpn.example.org'));
        expect((await harness.store.read())?.deploymentName, 'Home');
        expect(find.text('sign-in screen'), findsOneWidget);
      },
      variant: TargetPlatformVariant.only(TargetPlatform.android),
    );

    testWidgets(
      'a scanned link with a tampered pin is refused',
      (WidgetTester tester) async {
        // One hex digit changed: the same check a pasted link gets.
        final String tampered = (pin[0] == 'a' ? 'b' : 'a') + pin.substring(1);
        final _Harness harness = _Harness(preferences)
          ..scanResult =
              'https://vpn.example.org/pair#v=1&d=$_deployment&ca=$tampered';
        await _pump(tester, harness);

        await tester.tap(find.text('Scan QR code'));
        await tester.pumpAndSettle();

        expect(await harness.store.read(), isNull);
        expect(find.text('sign-in screen'), findsNothing);
        expect(
          find.textContaining("certificate doesn't match the link"),
          findsOneWidget,
        );
      },
      variant: TargetPlatformVariant.only(TargetPlatform.android),
    );

    testWidgets(
      'closing the scanner without a code changes nothing',
      (WidgetTester tester) async {
        final _Harness harness = _Harness(preferences);
        await _pump(tester, harness);

        await tester.tap(find.text('Scan QR code'));
        await tester.pumpAndSettle();

        expect(harness.scans, 1);
        expect(harness.fetched, isEmpty);
        expect(await harness.store.read(), isNull);
      },
      variant: TargetPlatformVariant.only(TargetPlatform.android),
    );
  });

  testWidgets(
    'Windows has no scanner and still pastes',
    (WidgetTester tester) async {
      await _pump(tester, _Harness(preferences));

      expect(find.text('Scan QR code'), findsNothing);
      expect(find.byType(TextFormField), findsOneWidget);
    },
    variant: TargetPlatformVariant.only(TargetPlatform.windows),
  );
}
