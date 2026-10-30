import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/xray/windows_network_monitor.dart';

void main() {
  // A WireGuard tunnel's adapter is named after the tunnel, "nebula". Matched
  // case-sensitively it was never found: the app took its own tunnel for
  // another VPN's and disconnected it seconds after it came up.
  test("finds the WireGuard tunnel's lowercase adapter", () {
    const String netsh = '''
   MTU  MediaSenseState   Bytes In  Bytes Out  Interface
------  ---------------  ---------  ---------  -------------
  1420                1       5120       2048  nebula
''';

    final RegExpMatch? match = WindowsNetworkMonitor.matchSubinterface(netsh);

    expect(match?.group(2), '1');
    expect(match?.group(3), '5120');
    expect(match?.group(4), '2048');
  });

  test('does not take another adapter for it', () {
    expect(
      WindowsNetworkMonitor.matchSubinterface(
        '  1500                1       100       200  Nebula Other\n',
      ),
      isNull,
    );
  });
}
