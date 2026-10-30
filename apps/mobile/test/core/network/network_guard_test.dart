import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/network/api_exception.dart';
import 'package:nebula_mobile/core/network/connectivity_state.dart';
import 'package:nebula_mobile/core/network/network_guard.dart';

/// `runGuarded` needs a real [Ref] (not a bare [ProviderContainer]) to call
/// [connectivityProvider]'s notifier, so this tiny notifier gives the test
/// a `ref` to drive it through.
class _Runner extends Notifier<int> {
  @override
  int build() => 0;

  Future<T> run<T>(Future<T> Function() call) => runGuarded(ref, call);
}

final _runnerProvider = NotifierProvider<_Runner, int>(_Runner.new);

void main() {
  test('a connectivity exception marks offline and rethrows', () async {
    final ProviderContainer container = ProviderContainer();
    addTearDown(container.dispose);
    final _Runner runner = container.read(_runnerProvider.notifier);

    await expectLater(
      runner.run(
        () => Future<int>.error(const NebulaConnectivityException('down')),
      ),
      throwsA(isA<NebulaConnectivityException>()),
    );

    expect(container.read(connectivityProvider), ConnectivityState.offline);
  });

  test('a successful call marks online again', () async {
    final ProviderContainer container = ProviderContainer();
    addTearDown(container.dispose);
    container.read(connectivityProvider.notifier).markOffline();
    final _Runner runner = container.read(_runnerProvider.notifier);

    final int result = await runner.run(() async => 42);

    expect(result, 42);
    expect(container.read(connectivityProvider), ConnectivityState.online);
  });

  test('a normal API error leaves connectivity untouched', () async {
    final ProviderContainer container = ProviderContainer();
    addTearDown(container.dispose);
    final _Runner runner = container.read(_runnerProvider.notifier);

    await expectLater(
      runner.run(
        () => Future<int>.error(
          const NebulaApiException(statusCode: 401, detail: 'nope'),
        ),
      ),
      throwsA(isA<NebulaApiException>()),
    );

    expect(container.read(connectivityProvider), ConnectivityState.online);
  });
}
