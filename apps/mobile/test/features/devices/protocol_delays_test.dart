import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/features/devices/devices_state.dart';

void main() {
  test("one server's test results are not another's", () {
    // Every server names its protocols the same way: results kept by name
    // alone showed on another server's chips and ranked its protocols.
    final DevicesState tested = DevicesState.initial.copyWith(
      protocolDelays: <String, ProtocolDelay>{
        'vless-ws-tls': ProtocolDelay.measured(120),
      },
      protocolDelaysServer: () => 'ams-1',
    );

    expect(tested.delaysFor('ams-1')['vless-ws-tls']?.milliseconds, 120);
    expect(tested.delaysFor('fra-2'), isEmpty);
    expect(tested.delaysFor(null), isEmpty);
  });
}
