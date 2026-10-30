import 'package:flutter/material.dart';

import '../../theme/color_tokens.dart';
import '../../theme/type_scale.dart';

/// A segmented control: equal segments in a bordered track.
///
/// 44px tall with a 12px radius, and the selected segment takes a `hairline`
/// fill with `textMax` on it. Not Material's `SegmentedButton`, which draws a
/// check on the selected segment and sizes itself to its content -- both
/// wrong here, where three equal segments and no ornament is the point.
class PanelSegmented<T> extends StatelessWidget {
  const PanelSegmented({
    required this.segments,
    required this.selected,
    required this.onChanged,
    super.key,
    this.semanticsLabel,
  });

  /// Ordered value/label pairs, left to right.
  final List<(T, String)> segments;
  final T selected;
  final ValueChanged<T> onChanged;

  /// Names the control as a whole for a screen reader.
  ///
  /// Without it the segments announce as three unrelated buttons reading
  /// "Light", "Dark", "System", with nothing saying what they set.
  final String? semanticsLabel;

  @override
  Widget build(BuildContext context) {
    final NebulaPalette palette = context.palette;
    final NebulaTypography type = context.type;

    final Widget track = Container(
      height: 44,
      decoration: BoxDecoration(
        border: Border.all(color: palette.border),
        borderRadius: BorderRadius.circular(12),
      ),
      // Clip so the selected segment's fill follows the track's corners
      // instead of squaring them off.
      clipBehavior: Clip.antiAlias,
      child: Row(
        children: <Widget>[
          for (final (T value, String label) in segments)
            Expanded(
              child: Semantics(
                button: true,
                // Announces "selected" rather than leaving the current choice
                // indistinguishable from the other two by voice.
                selected: value == selected,
                child: InkWell(
                  onTap: () => onChanged(value),
                  child: Container(
                    alignment: Alignment.center,
                    color: value == selected
                        ? palette.hairline
                        : Colors.transparent,
                    child: Text(
                      label,
                      style: type.tabLabel.copyWith(
                        color: value == selected
                            ? palette.textMax
                            : palette.textMuted,
                      ),
                    ),
                  ),
                ),
              ),
            ),
        ],
      ),
    );

    if (semanticsLabel == null) {
      return track;
    }
    return Semantics(container: true, label: semanticsLabel, child: track);
  }
}

/// A settings row: title over mono meta, with a control on the right.
///
/// Shares the data row's 18px rhythm and hairline rule, but the right-hand
/// side is a control rather than a value, and the whole row is the tap target
/// so the switch is not a 28px target in the corner of a 60px row.
class PanelToggleRow extends StatelessWidget {
  const PanelToggleRow({
    required this.title,
    required this.value,
    required this.onChanged,
    super.key,
    this.meta,
    this.isLast = false,
  });

  final String title;
  final String? meta;
  final bool value;
  final ValueChanged<bool> onChanged;
  final bool isLast;

  @override
  Widget build(BuildContext context) {
    final NebulaPalette palette = context.palette;
    final NebulaTypography type = context.type;

    return InkWell(
      onTap: () => onChanged(!value),
      child: Container(
        decoration: BoxDecoration(
          border: Border(
            top: BorderSide(color: palette.hairline),
            bottom: isLast
                ? BorderSide(color: palette.hairline)
                : BorderSide.none,
          ),
        ),
        padding: const EdgeInsets.symmetric(vertical: 18),
        child: Row(
          children: <Widget>[
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: <Widget>[
                  Text(
                    title,
                    style: type.listTitleInactive.copyWith(
                      color: palette.textPrimary,
                    ),
                  ),
                  if (meta != null) ...<Widget>[
                    const SizedBox(height: 3),
                    Text(
                      meta!,
                      style: type.listMeta.copyWith(color: palette.textMuted),
                    ),
                  ],
                ],
              ),
            ),
            const SizedBox(width: 14),
            // 48x28 with a 22px knob, per the spec. Material's Switch is
            // close enough at this size once the colours are pinned; a custom
            // one would be pixel-accurate and one more thing to maintain.
            Switch(
              value: value,
              onChanged: onChanged,
              activeThumbColor: palette.bg,
              activeTrackColor: palette.blue,
              inactiveThumbColor: palette.textMuted,
              inactiveTrackColor: palette.surface,
              trackOutlineColor: WidgetStatePropertyAll<Color>(palette.border),
            ),
          ],
        ),
      ),
    );
  }
}

/// A row that opens something outside the app.
///
/// Distinct from a navigational [PanelRow] because leaving for a system
/// screen is not the same promise as pushing a screen this app controls, and
/// the design marks it with `open_in_new` rather than a chevron.
class PanelExternalRow extends StatelessWidget {
  const PanelExternalRow({
    required this.title,
    required this.onTap,
    super.key,
    this.meta,
    this.metaColor,
    this.isLast = false,
  });

  final String title;
  final String? meta;
  final Color? metaColor;
  final VoidCallback onTap;
  final bool isLast;

  @override
  Widget build(BuildContext context) {
    final NebulaPalette palette = context.palette;
    final NebulaTypography type = context.type;

    return InkWell(
      onTap: onTap,
      child: Container(
        decoration: BoxDecoration(
          border: Border(
            top: BorderSide(color: palette.hairline),
            bottom: isLast
                ? BorderSide(color: palette.hairline)
                : BorderSide.none,
          ),
        ),
        padding: const EdgeInsets.symmetric(vertical: 18),
        child: Row(
          children: <Widget>[
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: <Widget>[
                  Text(
                    title,
                    style: type.listTitleInactive.copyWith(
                      color: palette.textPrimary,
                    ),
                  ),
                  if (meta != null) ...<Widget>[
                    const SizedBox(height: 3),
                    Text(
                      meta!,
                      style: type.listMeta.copyWith(
                        color: metaColor ?? palette.textMuted,
                      ),
                    ),
                  ],
                ],
              ),
            ),
            const SizedBox(width: 14),
            Icon(Icons.open_in_new, size: 20, color: palette.textMuted),
          ],
        ),
      ),
    );
  }
}
