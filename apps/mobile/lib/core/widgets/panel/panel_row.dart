import 'package:flutter/material.dart';

import '../../format/bidi.dart';
import '../../theme/color_tokens.dart';
import '../../theme/type_scale.dart';

/// A data row: label left, value right, on a hairline rule.
///
/// The repeating unit of the whole design. 18px of vertical padding and a 1px
/// top border; the last row in a group also draws a bottom border, which is
/// what [isLast] is for -- rows butt against each other, so only the final one
/// needs closing or the group has an open bottom edge.
///
/// A row with [onTap] draws a chevron and takes the accent colour on its
/// value, which is how the design distinguishes "this is a fact" from "this
/// goes somewhere".
class PanelRow extends StatelessWidget {
  const PanelRow({
    required this.label,
    required this.value,
    super.key,
    this.onTap,
    this.isLast = false,
    this.valueColor,
    this.valueIsMono = true,
  });

  final String label;
  final String value;

  /// Makes the row navigational: chevron, accent value, and a tap target.
  final VoidCallback? onTap;

  /// Draws the closing rule under this row.
  final bool isLast;

  /// Overrides the value colour, for a warning or an accent.
  final Color? valueColor;

  /// Values are mono by default because they are numbers, endpoints and
  /// identifiers. A value that is prose sets this false.
  final bool valueIsMono;

  @override
  Widget build(BuildContext context) {
    final NebulaPalette palette = context.palette;
    final NebulaTypography type = context.type;
    final bool navigational = onTap != null;

    final Color resolvedValueColor =
        valueColor ?? (navigational ? palette.blueText : palette.textPrimary);

    final Widget content = Container(
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
          Text(label, style: type.rowLabel.copyWith(color: palette.textMuted)),
          const SizedBox(width: 16),
          // Expanded, not a Spacer beside a loose Flexible: that pair split
          // the free space in half, so a short value started at the middle of
          // the row instead of sitting at its end.
          Expanded(
            child: Text(
              value,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              // A code, an address or a byte count reads left to right in any
              // language; left to the row's direction it is reordered and cut
              // from the wrong end. Aligned to the end of the row rather than
              // the end of the text, which is the other side when the two run
              // in different directions.
              textDirection: inherentDirection(value),
              textAlign: alignToRowEnd(context),
              style: (valueIsMono ? type.rowValue : type.rowLabel).copyWith(
                color: resolvedValueColor,
              ),
            ),
          ),
          if (navigational) ...<Widget>[
            const SizedBox(width: 6),
            Icon(Icons.chevron_right, size: 18, color: resolvedValueColor),
          ],
        ],
      ),
    );

    if (!navigational) {
      return content;
    }
    return InkWell(
      onTap: onTap,
      // The rule spans the full width, so the ripple should too rather than
      // inset itself and leave the borders looking detached.
      child: content,
    );
  }
}

/// A group of [PanelRow]s that closes its own bottom edge.
///
/// Saves every caller remembering `isLast` on the final child, which is the
/// kind of thing that is only noticed when a designer looks at it.
class PanelRowGroup extends StatelessWidget {
  const PanelRowGroup({required this.rows, super.key});

  final List<PanelRow> rows;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: <Widget>[
        for (int i = 0; i < rows.length; i++)
          if (i == rows.length - 1)
            PanelRow(
              label: rows[i].label,
              value: rows[i].value,
              onTap: rows[i].onTap,
              valueColor: rows[i].valueColor,
              valueIsMono: rows[i].valueIsMono,
              isLast: true,
            )
          else
            rows[i],
      ],
    );
  }
}
