import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'api_exception.dart';
import 'connectivity_state.dart';

/// Runs [call], updating [connectivityProvider] based on whether it failed
/// because the API was unreachable or succeeded/failed normally.
///
/// Screens and notifiers that call the API route through this so "offline"
/// is observed consistently in one place, rather than each call site
/// re-deriving it from a caught exception -- and so offline is treated as a
/// distinct UI state from "the server said no."
Future<T> runGuarded<T>(Ref ref, Future<T> Function() call) async {
  try {
    final T result = await call();
    ref.read(connectivityProvider.notifier).markOnline();
    return result;
  } on NebulaConnectivityException {
    ref.read(connectivityProvider.notifier).markOffline();
    rethrow;
  }
}
