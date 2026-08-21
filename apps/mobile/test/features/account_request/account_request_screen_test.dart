import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/auth/auth_repository.dart';
import 'package:nebula_mobile/features/account_request/account_request_screen.dart';

import '../../core/auth/fake_auth_repository.dart';

const String _neutralCopy =
    'If that email is eligible, you will receive activation '
    'instructions shortly.';

Future<void> _pumpAndSubmit(
  WidgetTester tester,
  FakeAuthRepository repository,
) async {
  await tester.pumpWidget(
    ProviderScope(
      overrides: <Override>[
        authRepositoryProvider.overrideWithValue(repository),
      ],
      child: const MaterialApp(home: AccountRequestScreen()),
    ),
  );

  await tester.enterText(
    find.byType(TextFormField).first,
    'user@example.com',
  );
  await tester.tap(find.widgetWithText(FilledButton, 'Submit request'));
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('shows the same neutral copy on a plain success', (
    WidgetTester tester,
  ) async {
    final FakeAuthRepository repository = FakeAuthRepository();
    await _pumpAndSubmit(tester, repository);

    expect(find.text(_neutralCopy), findsOneWidget);
    expect(repository.submitAccountRequestCalls, 1);
  });

  testWidgets('client-side validation runs before any request is made', (
    WidgetTester tester,
  ) async {
    final FakeAuthRepository repository = FakeAuthRepository();
    await tester.pumpWidget(
      ProviderScope(
        overrides: <Override>[
          authRepositoryProvider.overrideWithValue(repository),
        ],
        child: const MaterialApp(home: AccountRequestScreen()),
      ),
    );

    // Leave the email field invalid to prove client-side validation runs
    // before any request -- the API is never consulted for an obviously
    // malformed submission.
    await tester.tap(find.widgetWithText(FilledButton, 'Submit request'));
    await tester.pump();

    expect(find.text('Enter a valid email'), findsOneWidget);
    expect(find.text(_neutralCopy), findsNothing);
    expect(repository.submitAccountRequestCalls, 0);
  });
}
