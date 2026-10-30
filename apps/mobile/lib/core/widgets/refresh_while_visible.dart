import 'dart:async';

import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

/// Keeps a tab's figures current while somebody is looking at them.
///
/// The home tabs stay built when another one is showing, so a screen that
/// loads once, in initState, goes on showing what it loaded: the account
/// screen said "0 / 30 MB used" for twenty minutes after the allowance was
/// spent. A hidden tab has tickers turned off -- go_router wraps inactive
/// branches in `TickerMode(enabled: false)` -- and depending on that is what
/// calls didChangeDependencies again when the tab is switched to.
///
/// Refreshes when the screen becomes visible, when the app comes back to the
/// foreground, and every [refreshInterval] while both hold.
mixin RefreshWhileVisible<T extends ConsumerStatefulWidget>
    on ConsumerState<T> {
  Timer? _refreshTimer;
  AppLifecycleListener? _lifecycle;
  bool _visible = false;
  bool _foreground = true;

  /// How often to fetch again while the screen is showing.
  Duration get refreshInterval;

  /// Fetches again. Never called during a build.
  void refresh();

  @override
  void initState() {
    super.initState();
    _lifecycle = AppLifecycleListener(
      onStateChange: (AppLifecycleState lifecycle) {
        final bool foreground = lifecycle == AppLifecycleState.resumed;
        if (foreground != _foreground) {
          _foreground = foreground;
          _follow(refreshNow: foreground);
        }
      },
    );
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    final bool visible = TickerMode.valuesOf(context).enabled;
    if (visible != _visible) {
      _visible = visible;
      _follow(refreshNow: visible);
    }
  }

  void _follow({required bool refreshNow}) {
    _refreshTimer?.cancel();
    _refreshTimer = null;
    if (!_visible || !_foreground) {
      return;
    }
    if (refreshNow) {
      // After the frame: this can run while the tree is building, and a
      // first refresh is a load, which changes state -- not allowed mid-build.
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted) {
          refresh();
        }
      });
    }
    _refreshTimer = Timer.periodic(refreshInterval, (_) => refresh());
  }

  @override
  void dispose() {
    _refreshTimer?.cancel();
    _lifecycle?.dispose();
    super.dispose();
  }
}
