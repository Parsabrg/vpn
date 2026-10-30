import 'package:flutter/material.dart';

import '../../core/theme/color_tokens.dart';
import '../../core/theme/reduced_motion.dart';
import '../../core/theme/type_scale.dart';
import '../../l10n/app_localizations.dart';

/// Purely presentational. `AuthNotifier.bootstrap()` runs once from
/// `main.dart` before the app is even built (see there for why), and the
/// router's redirect moves away from this screen automatically once
/// [AuthState] resolves to authenticated or unauthenticated -- this widget
/// never has to drive navigation itself.
///
/// The wordmark and a short track, with no shield and no spinner. A spinner
/// here would be the app's first statement about itself, and a spinner says
/// "waiting" where this is usually gone within a frame or two.
///
/// A server that could not be reached is no longer explained here: the app
/// opens on its saved settings instead, says so on Connect, and
/// [AuthNotifier] keeps trying in the background. This screen waited, and
/// waiting was the one thing that could not help on a blocked address.
class SplashScreen extends StatelessWidget {
  const SplashScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final NebulaPalette palette = context.palette;

    return Scaffold(
      backgroundColor: palette.bg,
      body: Center(
        child: Semantics(
          label: AppText.of(context).loadingNebula,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: <Widget>[
              Text(
                'NEBULA',
                style: context.type.wordmark.copyWith(
                  color: palette.textPrimary,
                  letterSpacing: 4,
                ),
              ),
              const SizedBox(height: 20),
              const _BootTrack(),
            ],
          ),
        ),
      ),
    );
  }
}

/// A 64x2 track with a blue fill that travels along it.
///
/// Indeterminate on purpose: bootstrap has no measurable progress, and a bar
/// that filled to a fraction would be inventing one. Under reduced motion it
/// is a static partial fill, which still reads as "starting" without moving.
class _BootTrack extends StatefulWidget {
  const _BootTrack();

  @override
  State<_BootTrack> createState() => _BootTrackState();
}

class _BootTrackState extends State<_BootTrack>
    with SingleTickerProviderStateMixin {
  late final AnimationController _controller = AnimationController(
    vsync: this,
    duration: const Duration(milliseconds: 1200),
  )..repeat(reverse: true);

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final NebulaPalette palette = context.palette;
    const double trackWidth = 64;
    const double fillWidth = 26;

    final Widget track = Container(
      width: trackWidth,
      height: 2,
      color: palette.hairline,
    );

    if (effectiveDuration(context, const Duration(seconds: 1)) ==
        Duration.zero) {
      return Stack(
        children: <Widget>[
          track,
          Container(width: fillWidth, height: 2, color: palette.blue),
        ],
      );
    }

    return AnimatedBuilder(
      animation: _controller,
      builder: (BuildContext context, Widget? child) {
        return Stack(
          children: <Widget>[
            track,
            Positioned(
              left: (trackWidth - fillWidth) * _controller.value,
              child: Container(
                width: fillWidth,
                height: 2,
                color: palette.blue,
              ),
            ),
          ],
        );
      },
    );
  }
}

/// The server could not be reached, and the session is kept.
///
/// Laid out like the Connect screen's own unreachable state, so the two read
/// as the same situation. Retries on its own every so often, because the
/// usual cause -- no network -- fixes itself without anyone pressing a button.
/// The next attempt is timed from the end of the last one rather than on a
/// fixed beat: an attempt can take the whole ten-second connect timeout, and
/// on a fifteen-second beat that left Try again disabled most of the time.
///
/// Offers to turn the VPN off when this app's tunnel is up: a tunnel that
/// is up but carrying nothing is itself a reason the server cannot be
/// reached, and its Disconnect button is behind the session this screen is
/// waiting for.
