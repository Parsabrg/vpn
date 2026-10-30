import 'package:flutter/material.dart';

import '../../theme/color_tokens.dart';
import '../../theme/type_scale.dart';

/// How a call to action is filled.
enum CtaStyle {
  /// Blue fill. The forward action: Connect, Try again, Refresh.
  primary,

  /// Border only. The undoing action: Cancel, Disconnect, Sign out.
  ///
  /// Disconnect is deliberately not red. Ending a session you asked for is
  /// not an error, and the design reserves red for the unreachable state.
  secondary,

  /// Amber fill. Only for retrying a tunnel from the peer-only state, where
  /// the whole screen is amber and a blue button would read as success.
  warning,
}

/// The full-width action at the thumb.
///
/// 60px tall with a 14px radius, inside the 20px insets the design gives the
/// CTA block. One widget for all three fills so the geometry cannot drift
/// between screens, which is the usual way a design like this comes apart.
class PanelCta extends StatelessWidget {
  const PanelCta({
    required this.label,
    required this.onPressed,
    super.key,
    this.style = CtaStyle.primary,
    this.icon,
  });

  final String label;

  /// A null callback disables the button, which the design draws as a flat
  /// `surface` block with muted text rather than a dimmed fill.
  final VoidCallback? onPressed;

  final CtaStyle style;
  final IconData? icon;

  @override
  Widget build(BuildContext context) {
    final NebulaPalette palette = context.palette;
    final NebulaTypography type = context.type;
    final bool enabled = onPressed != null;

    final Widget content = Row(
      mainAxisAlignment: MainAxisAlignment.center,
      children: <Widget>[
        if (icon != null) ...<Widget>[
          Icon(icon, size: 20),
          const SizedBox(width: 8),
        ],
        Text(label, style: type.ctaLabel),
      ],
    );

    final ButtonStyle buttonStyle;
    switch (style) {
      case CtaStyle.primary:
        buttonStyle = FilledButton.styleFrom(
          backgroundColor: palette.blue,
          foregroundColor: palette.onAccent,
          disabledBackgroundColor: palette.surface,
          disabledForegroundColor: palette.textMuted,
        );
      case CtaStyle.warning:
        buttonStyle = FilledButton.styleFrom(
          backgroundColor: palette.amber,
          foregroundColor: palette.onAccent,
          disabledBackgroundColor: palette.surface,
          disabledForegroundColor: palette.textMuted,
        );
      case CtaStyle.secondary:
        buttonStyle = FilledButton.styleFrom(
          backgroundColor: Colors.transparent,
          foregroundColor: palette.textPrimary,
          disabledBackgroundColor: palette.surface,
          disabledForegroundColor: palette.textMuted,
          side: BorderSide(
            color: enabled ? palette.borderStrong : palette.border,
          ),
        );
    }

    return SizedBox(
      height: 60,
      width: double.infinity,
      child: FilledButton(
        onPressed: onPressed,
        style: buttonStyle.copyWith(
          shape: WidgetStatePropertyAll<OutlinedBorder>(
            RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
          ),
          // Flat by design: elevation would put a shadow on a near-black
          // background, which reads as a smudge rather than as depth.
          elevation: const WidgetStatePropertyAll<double>(0),
        ),
        child: content,
      ),
    );
  }
}

/// The inert block the loading state shows where the CTA will be.
///
/// Not a disabled [PanelCta]: there is no label yet, and a button with no
/// text that cannot be pressed is a worse thing to hand a screen reader than
/// a plain decorative box.
class PanelCtaPlaceholder extends StatelessWidget {
  const PanelCtaPlaceholder({super.key});

  @override
  Widget build(BuildContext context) {
    return ExcludeSemantics(
      child: Container(
        height: 60,
        width: double.infinity,
        decoration: BoxDecoration(
          color: context.palette.surface,
          borderRadius: BorderRadius.circular(14),
        ),
      ),
    );
  }
}
