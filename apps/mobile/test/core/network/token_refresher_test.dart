import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/auth/token_pair.dart';
import 'package:nebula_mobile/core/network/token_refresher.dart';

void main() {
  group('TokenRefresher', () {
    test(
      'deduplicates concurrent refresh calls into a single network call',
      () async {
        int callCount = 0;
        final Completer<TokenPair> gate = Completer<TokenPair>();

        final TokenRefresher refresher = TokenRefresher(() {
          callCount++;
          return gate.future;
        });

        // Five callers arrive before the underlying call resolves.
        final List<Future<TokenPair>> pending =
            List<Future<TokenPair>>.generate(5, (_) => refresher.refresh());

        // No caller has resolved yet, but the underlying call must have
        // fired exactly once.
        expect(callCount, 1);

        const TokenPair result = TokenPair(
          accessToken: 'new-access',
          refreshToken: 'new-refresh',
          expiresIn: Duration(minutes: 15),
        );
        gate.complete(result);

        final List<TokenPair> results = await Future.wait(pending);
        expect(results, everyElement(same(result)));
        expect(callCount, 1);
      },
    );

    test('a later refresh after completion starts a new call', () async {
      int callCount = 0;
      final TokenRefresher refresher = TokenRefresher(() async {
        callCount++;
        return TokenPair(
          accessToken: 'access-$callCount',
          refreshToken: 'refresh-$callCount',
          expiresIn: const Duration(minutes: 15),
        );
      });

      final TokenPair first = await refresher.refresh();
      final TokenPair second = await refresher.refresh();

      expect(callCount, 2);
      expect(first.accessToken, 'access-1');
      expect(second.accessToken, 'access-2');
    });

    test(
      'every concurrent caller receives the same error when refresh fails',
      () async {
        int callCount = 0;
        final Completer<TokenPair> gate = Completer<TokenPair>();

        final TokenRefresher refresher = TokenRefresher(() {
          callCount++;
          return gate.future;
        });

        final Future<TokenPair> first = refresher.refresh();
        final Future<TokenPair> second = refresher.refresh();

        final Exception failure = Exception('refresh rejected');
        gate.completeError(failure);

        await expectLater(first, throwsA(same(failure)));
        await expectLater(second, throwsA(same(failure)));
        expect(callCount, 1);
      },
    );
  });
}
