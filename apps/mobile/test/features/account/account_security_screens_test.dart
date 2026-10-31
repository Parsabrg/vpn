import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_riverpod/misc.dart' show Override;
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/account/account_repository.dart';
import 'package:nebula_mobile/core/auth/auth_notifier.dart';
import 'package:nebula_mobile/core/auth/auth_state.dart';
import 'package:nebula_mobile/core/network/api_exception.dart';
import 'package:nebula_mobile/core/storage/storage_providers.dart';
import 'package:nebula_mobile/core/widgets/password_field.dart';
import 'package:nebula_mobile/features/account/account_security_screens.dart';
import 'package:nebula_mobile/features/devices/devices_controller.dart';
import 'package:nebula_mobile/features/devices/devices_state.dart';
import 'package:nebula_mobile/l10n/app_localizations.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../../core/account/fake_account_repository.dart';

/// Counts the tunnel being stopped after the account is gone.
class _Devices extends DevicesController {
  int ended = 0;

  @override
  DevicesState build() => DevicesState.initial;

  @override
  Future<void> endAfterSessionLost() async => ended++;
}

/// Counts sign-outs; nothing else of the session machinery runs.
class _Auth extends AuthNotifier {
  int loggedOut = 0;

  @override
  AuthState build() => const AuthUnauthenticated();

  @override
  Future<void> logout() async => loggedOut++;
}

const NebulaApiException _wrongPassword = NebulaApiException(
  statusCode: 403,
  detail: 'password_not_accepted',
);

Future<void> _pump(
  WidgetTester tester,
  Widget screen, {
  required FakeAccountRepository repository,
  _Devices? devices,
  _Auth? auth,
}) async {
  SharedPreferences.setMockInitialValues(<String, Object>{});
  final SharedPreferences preferences = await SharedPreferences.getInstance();
  await tester.pumpWidget(
    ProviderScope(
      overrides: <Override>[
        accountRepositoryProvider.overrideWithValue(repository),
        sharedPreferencesProvider.overrideWithValue(preferences),
        devicesControllerProvider.overrideWith(() => devices ?? _Devices()),
        authNotifierProvider.overrideWith(() => auth ?? _Auth()),
      ],
      child: MaterialApp(
        localizationsDelegates: AppText.localizationsDelegates,
        supportedLocales: AppText.supportedLocales,
        home: screen,
      ),
    ),
  );
}

Finder _passwordBox(int index) => find
    .descendant(
      of: find.byType(PasswordField),
      matching: find.byType(EditableText),
    )
    .at(index);

void main() {
  group('changing the password', () {
    testWidgets('sends the current and the new password', (
      WidgetTester tester,
    ) async {
      final FakeAccountRepository repository = FakeAccountRepository();
      await _pump(tester, const ChangePasswordScreen(), repository: repository);

      await tester.enterText(_passwordBox(0), 'old-password');
      await tester.enterText(_passwordBox(1), 'a-new-password-12');
      await tester.tap(find.widgetWithText(FilledButton, 'Change password'));
      await tester.pumpAndSettle();

      expect(repository.securityCalls, <String>[
        'change:old-password>a-new-password-12',
      ]);
    });

    testWidgets('a short new password is not sent', (
      WidgetTester tester,
    ) async {
      final FakeAccountRepository repository = FakeAccountRepository();
      await _pump(tester, const ChangePasswordScreen(), repository: repository);

      await tester.enterText(_passwordBox(0), 'old-password');
      await tester.enterText(_passwordBox(1), 'short');
      await tester.tap(find.widgetWithText(FilledButton, 'Change password'));
      await tester.pumpAndSettle();

      expect(repository.securityCalls, isEmpty);
      expect(find.text('Use at least 12 characters'), findsOneWidget);
    });

    testWidgets('a wrong current password says so', (
      WidgetTester tester,
    ) async {
      final FakeAccountRepository repository = FakeAccountRepository()
        ..securityError = _wrongPassword;
      await _pump(tester, const ChangePasswordScreen(), repository: repository);

      await tester.enterText(_passwordBox(0), 'not-it');
      await tester.enterText(_passwordBox(1), 'a-new-password-12');
      await tester.tap(find.widgetWithText(FilledButton, 'Change password'));
      await tester.pumpAndSettle();

      expect(find.text('That is not your password.'), findsOneWidget);
    });
  });

  group('deleting the account', () {
    testWidgets('stops the tunnel and signs out once the server deleted it', (
      WidgetTester tester,
    ) async {
      final FakeAccountRepository repository = FakeAccountRepository();
      final _Devices devices = _Devices();
      final _Auth auth = _Auth();
      await _pump(
        tester,
        const DeleteAccountScreen(),
        repository: repository,
        devices: devices,
        auth: auth,
      );

      expect(find.textContaining('30 days'), findsOneWidget);
      await tester.enterText(_passwordBox(0), 'the-password');
      await tester.tap(find.text('Delete my account'));
      await tester.pumpAndSettle();

      expect(repository.securityCalls, <String>['delete:the-password']);
      expect(devices.ended, 1);
      expect(auth.loggedOut, 1);
      expect(find.text('Your account was deleted.'), findsOneWidget);
    });

    testWidgets('a wrong password keeps the session and the tunnel', (
      WidgetTester tester,
    ) async {
      final FakeAccountRepository repository = FakeAccountRepository()
        ..securityError = _wrongPassword;
      final _Devices devices = _Devices();
      final _Auth auth = _Auth();
      await _pump(
        tester,
        const DeleteAccountScreen(),
        repository: repository,
        devices: devices,
        auth: auth,
      );

      await tester.enterText(_passwordBox(0), 'not-it');
      await tester.tap(find.text('Delete my account'));
      await tester.pumpAndSettle();

      expect(find.text('That is not your password.'), findsOneWidget);
      expect(devices.ended, 0);
      expect(auth.loggedOut, 0);
    });
  });
}
