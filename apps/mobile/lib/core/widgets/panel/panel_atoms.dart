import 'dart:math' as math;

import 'package:flutter/material.dart';

import '../../format/case.dart';
import '../../theme/color_tokens.dart';
import '../../theme/reduced_motion.dart';
import '../../theme/type_scale.dart';

/// What the dot beside the status line is saying.
enum StatusTone {
  /// Disconnected. A flat grey dot.
  off,

  /// A request is in flight. A 2px arc that spins.
  working,

  /// A live tunnel. A blue dot breathing between 0.6 and 1.0 opacity.
  live,

  /// Peer-only, or another warning.
  warning,

  /// Unreachable.
  error,
}

/// The dot that precedes the status line.
///
/// Motion is part of the meaning here rather than decoration: the spinning arc
/// says a handshake is happening, and the breathing dot says the tunnel is
/// still up right now, which a static dot cannot distinguish from a stale
/// screen. Both collapse to a still dot under reduced motion, where the colour
/// still carries the state.
class StatusDot extends StatelessWidget {
  const StatusDot({required this.tone, super.key, this.size = 8});

  final StatusTone tone;
  final double size;

  @override
  Widget build(BuildContext context) {
    final NebulaPalette palette = context.palette;
    final bool still =
        effectiveDuration(context, const Duration(seconds: 1)) == Duration.zero;

    switch (tone) {
      case StatusTone.off:
        return _Dot(color: palette.dotOff, size: size);
      case StatusTone.warning:
        return _Dot(color: palette.amber, size: size);
      case StatusTone.error:
        return _Dot(color: palette.red, size: size);
      case StatusTone.live:
        if (still) {
          return _Dot(color: palette.blue, size: size);
        }
        return _PulsingDot(color: palette.blue, size: size);
      case StatusTone.working:
        if (still) {
          return _Dot(color: palette.blue, size: size);
        }
        return _SpinningArc(color: palette.blue, size: size + 4);
    }
  }
}

class _Dot extends StatelessWidget {
  const _Dot({required this.color, required this.size});

  final Color color;
  final double size;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(color: color, shape: BoxShape.circle),
    );
  }
}

/// 2.4 rad/s sine between 0.6 and 1.0 opacity, per the motion spec.
class _PulsingDot extends StatefulWidget {
  const _PulsingDot({required this.color, required this.size});

  final Color color;
  final double size;

  @override
  State<_PulsingDot> createState() => _PulsingDotState();
}

class _PulsingDotState extends State<_PulsingDot>
    with SingleTickerProviderStateMixin {
  late final AnimationController _controller = AnimationController(
    vsync: this,
    // One full sine period at 2.4 rad/s is 2*pi/2.4 = 2.618s.
    duration: const Duration(milliseconds: 2618),
  )..repeat();

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _controller,
      builder: (BuildContext context, Widget? child) {
        final double sine = math.sin(_controller.value * 2 * math.pi);
        // Map -1..1 onto the specified 0.6..1.0.
        final double opacity = 0.8 + 0.2 * sine;
        return Opacity(opacity: opacity, child: child);
      },
      child: _Dot(color: widget.color, size: widget.size),
    );
  }
}

/// A 2px arc turning at 400 degrees per second, per the motion spec.
class _SpinningArc extends StatefulWidget {
  const _SpinningArc({required this.color, required this.size});

  final Color color;
  final double size;

  @override
  State<_SpinningArc> createState() => _SpinningArcState();
}

class _SpinningArcState extends State<_SpinningArc>
    with SingleTickerProviderStateMixin {
  late final AnimationController _controller = AnimationController(
    vsync: this,
    // 360 degrees at 400 deg/s is 900ms.
    duration: const Duration(milliseconds: 900),
  )..repeat();

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: widget.size,
      height: widget.size,
      child: RotationTransition(
        turns: _controller,
        child: CustomPaint(painter: _ArcPainter(widget.color)),
      ),
    );
  }
}

class _ArcPainter extends CustomPainter {
  const _ArcPainter(this.color);

  final Color color;

  @override
  void paint(Canvas canvas, Size size) {
    final Paint paint = Paint()
      ..color = color
      ..strokeWidth = 2
      ..style = PaintingStyle.stroke
      ..strokeCap = StrokeCap.round;
    canvas.drawArc(
      Offset.zero & size,
      -math.pi / 2,
      // Three quarters of the circle, so the gap reads as motion.
      math.pi * 1.5,
      false,
      paint,
    );
  }

  @override
  bool shouldRepaint(_ArcPainter oldDelegate) => oldDelegate.color != color;
}

/// The uppercase mono line above the state word: dot, then text.
class StatusLine extends StatelessWidget {
  const StatusLine({required this.tone, required this.text, super.key});

  final StatusTone tone;
  final String text;

  @override
  Widget build(BuildContext context) {
    final NebulaPalette palette = context.palette;
    final Color color;
    switch (tone) {
      case StatusTone.error:
        color = palette.redText;
      case StatusTone.warning:
        color = palette.amberDim;
      case StatusTone.live:
      case StatusTone.working:
      case StatusTone.off:
        color = palette.textMuted;
    }

    // A minimum rather than a fixed height: 16 fits Latin text, but Arabic
    // letters with descenders need more, and a fixed box clipped them.
    return ConstrainedBox(
      constraints: const BoxConstraints(minHeight: 16),
      child: Row(
        children: <Widget>[
          StatusDot(tone: tone),
          const SizedBox(width: 8),
          Flexible(
            child: Text(
              upperCaseFor(context, text),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: context.type.statusLine.copyWith(color: color),
            ),
          ),
        ],
      ),
    );
  }
}

/// The uppercase mono rule above a group of rows.
class SectionHeader extends StatelessWidget {
  const SectionHeader(this.label, {super.key});

  final String label;

  @override
  Widget build(BuildContext context) {
    return Text(
      upperCaseFor(context, label),
      style: context.type.sectionHeader.copyWith(
        color: context.palette.textMuted,
      ),
    );
  }
}

/// A pill-shaped placeholder that breathes on a 1.6s cycle.
///
/// The handoff is specific that the loading state is a skeleton and not a
/// spinner, sized and positioned where the real content will be, so the screen
/// does not jump when it arrives.
class SkeletonBar extends StatefulWidget {
  const SkeletonBar({required this.width, super.key, this.height = 16});

  final double width;
  final double height;

  @override
  State<SkeletonBar> createState() => _SkeletonBarState();
}

class _SkeletonBarState extends State<SkeletonBar>
    with SingleTickerProviderStateMixin {
  late final AnimationController _controller = AnimationController(
    vsync: this,
    duration: const Duration(milliseconds: 1600),
  )..repeat(reverse: true);

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final Widget bar = Container(
      width: widget.width,
      height: widget.height,
      decoration: BoxDecoration(
        color: context.palette.hairline,
        borderRadius: BorderRadius.circular(widget.height / 2),
      ),
    );

    if (effectiveDuration(context, const Duration(seconds: 1)) ==
        Duration.zero) {
      return bar;
    }
    return FadeTransition(
      opacity: Tween<double>(
        begin: 0.55,
        end: 1,
      ).animate(CurvedAnimation(parent: _controller, curve: Curves.easeInOut)),
      child: bar,
    );
  }
}

/// A protocol chip.
///
/// 100px radius so it is a true pill at any label length, and 9x14 padding
/// per the spec. Selected takes a blue border over a 10% blue wash rather
/// than a solid fill -- a filled chip at this size competes with the CTA,
/// which is the only thing on the screen that should read as the action.
class PanelChip extends StatelessWidget {
  const PanelChip({
    required this.label,
    required this.selected,
    super.key,
    this.onTap,
  });

  final String label;
  final bool selected;
  final VoidCallback? onTap;

  @override
  Widget build(BuildContext context) {
    final NebulaPalette palette = context.palette;
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(100),
      child: Container(
        padding: const EdgeInsets.symmetric(vertical: 9, horizontal: 14),
        decoration: BoxDecoration(
          color: selected
              ? palette.blue.withValues(alpha: 0.1)
              : Colors.transparent,
          border: Border.all(color: selected ? palette.blue : palette.border),
          borderRadius: BorderRadius.circular(100),
        ),
        child: Text(
          label,
          style: context.type.chipLabel.copyWith(
            color: selected ? palette.blueText : palette.textMuted,
          ),
        ),
      ),
    );
  }
}
