import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../storage/storage_providers.dart';

/// Which apps are routed around the tunnel, and nothing else.
///
/// Exclusions rather than inclusions. The two are not symmetric in practice:
/// a person who wants their banking app outside the tunnel wants everything
/// else inside it, and an inclusion list silently stops covering anything
/// installed afterwards. A new app is protected by default here, which is the
/// safer direction for a tool whose whole job is to carry traffic.
class SplitTunnelController extends Notifier<Set<String>> {
  @override
  Set<String> build() {
    return ref.watch(splitTunnelStoreProvider).readExcludedPackages();
  }

  bool isExcluded(String packageName) => state.contains(packageName);

  Future<void> setExcluded(String packageName, {required bool excluded}) {
    final Set<String> next = Set<String>.of(state);
    if (excluded) {
      next.add(packageName);
    } else {
      next.remove(packageName);
    }
    return _write(next);
  }

  Future<void> clear() => _write(<String>{});

  Future<void> _write(Set<String> next) async {
    // State first, so the switch moves under the finger rather than after a
    // disk round trip -- the same trade the protection toggles make.
    state = next;
    await ref.read(splitTunnelStoreProvider).writeExcludedPackages(next);
  }
}

final NotifierProvider<SplitTunnelController, Set<String>>
splitTunnelControllerProvider =
    NotifierProvider<SplitTunnelController, Set<String>>(
      SplitTunnelController.new,
    );

/// What the tunnel backends are handed.
///
/// A list, sorted, because both backends take an ordered collection and a Set
/// iterating differently between runs would make two identical configurations
/// compare as different.
List<String> excludedPackagesFor(Set<String> selection) {
  final List<String> ordered = selection.toList()..sort();
  return ordered;
}
