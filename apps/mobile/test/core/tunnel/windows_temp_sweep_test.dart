import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/tunnel/windows_temp_sweep.dart';

void main() {
  // Closed at the wrong moment, the Windows app left a WireGuard private key
  // and an Xray credential in the temp folder. The next start removes them,
  // and nothing a running tunnel still needs.
  late Directory root;

  setUp(() async {
    root = await Directory.systemTemp.createTemp('sweep-test-');
  });
  tearDown(() async {
    await root.delete(recursive: true);
  });

  Future<Directory> folder(String name, {Map<String, String>? files}) async {
    final Directory dir = await Directory('${root.path}/$name').create();
    for (final MapEntry<String, String> file
        in (files ?? <String, String>{}).entries) {
      await File('${dir.path}/${file.key}').writeAsString(file.value);
    }
    return dir;
  }

  Future<Set<String>> left() async => (await root.list().toList())
      .map((FileSystemEntity e) => e.uri.pathSegments.lastWhere((s) => s != ''))
      .toSet();

  test('removes what a gone app left, keeps a running tunnel', () async {
    await folder('nebula-wg-a1', files: {'nebula.conf': 'PrivateKey = x'});
    await folder(
      'nebula-tun-stopped',
      files: {'xray.json': '{}', 'stopped': ''},
    );
    await folder(
      'nebula-tun-dead',
      files: {'xray.json': '{}', 'xray.pid': '222'},
    );
    await folder(
      'nebula-tun-live',
      files: {'xray.json': '{}', 'xray.pid': '111'},
    );
    await folder('nebula-probe-new', files: {'xray.json': '{}'});
    await folder('something-else', files: {'keep': ''});

    await sweepStaleTunnelFolders(
      root: root,
      running: (int pid) async => pid == 111,
    );

    expect(await left(), <String>{
      'nebula-tun-live',
      'nebula-probe-new',
      'something-else',
    });
  });

  test('removes a probe or unstarted tunnel only once it is old', () async {
    await folder('nebula-probe-old', files: {'xray.json': '{}'});
    await folder('nebula-tun-unstarted', files: {'xray.json': '{}'});

    await sweepStaleTunnelFolders(root: root, running: (int _) async => true);
    expect(await left(), <String>{'nebula-probe-old', 'nebula-tun-unstarted'});

    await sweepStaleTunnelFolders(
      root: root,
      now: DateTime.now().add(const Duration(hours: 1)),
      running: (int _) async => true,
    );
    expect(await left(), isEmpty);
  });
}
