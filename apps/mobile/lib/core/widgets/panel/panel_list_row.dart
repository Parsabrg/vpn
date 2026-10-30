import 'package:flutter/material.dart';

import '../../format/bidi.dart';
import '../../theme/color_tokens.dart';
import '../../theme/type_scale.dart';

/// A selectable row in a list: title over mono meta, with something on the
/// right.
///
/// Distinct from `PanelRow`, which is a label/value pair stating a fact. This
/// one is an object you can choose or act on -- a server, a device -- so it is
/// taller (16px vertical to the data row's 18px, but two lines of content),
/// carries a subtitle, and can show a selection check.
///
/// [trailing] is text rather than a widget because in every use the design has
/// it is a mono figure: a latency, a count, a relative time. A row that needs
/// a button on the right uses [action] instead, which the design draws as a
/// text button rather than an icon.
class PanelListRow extends StatelessWidget {
  const PanelListRow({
    required this.title,
    super.key,
    this.meta,
    this.trailing,
    this.selected = false,
    this.onTap,
    this.leading,
    this.action,
    this.metaColor,
  });

  final String title;

  /// The mono sub-line. `null` renders a single-line row.
  final String? meta;

  /// Right-hand mono figure. `null` where there is nothing to show -- which
  /// is the honest rendering for latency until an endpoint serves it.
  final String? trailing;

  /// Draws the check and switches the title to its active weight.
  final bool selected;

  final VoidCallback? onTap;

  /// A platform or category icon, 20px, before the title.
  final IconData? leading;

  /// A trailing text action, e.g. Revoke. Mutually exclusive with [trailing]
  /// in every screen of the design, but not enforced -- a future row may want
  /// both, and nothing breaks if it does.
  final Widget? action;

  /// Overrides the meta colour, which the devices screen uses to mark the
  /// current device in the accent.
  final Color? metaColor;

  @override
  Widget build(BuildContext context) {
    final NebulaPalette palette = context.palette;
    final NebulaTypography type = context.type;

    final Widget row = Container(
      decoration: BoxDecoration(
        border: Border(top: BorderSide(color: palette.hairline)),
      ),
      padding: const EdgeInsets.symmetric(vertical: 16),
      child: Row(
        children: <Widget>[
          if (leading != null) ...<Widget>[
            Icon(leading, size: 20, color: palette.textMuted),
            const SizedBox(width: 14),
          ],
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: <Widget>[
                Text(
                  title,
                  style:
                      (selected ? type.listTitleActive : type.listTitleInactive)
                          .copyWith(color: palette.textPrimary),
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
          if (trailing != null) ...<Widget>[
            const SizedBox(width: 14),
            Text(
              trailing!,
              // "123 ms" stays in that order on a right-to-left screen.
              textDirection: inherentDirection(trailing!),
              style: type.rowValue.copyWith(color: palette.textMuted),
            ),
          ],
          if (action != null) ...<Widget>[const SizedBox(width: 14), action!],
          if (selected) ...<Widget>[
            const SizedBox(width: 14),
            Icon(Icons.check, size: 20, color: palette.blue),
          ],
        ],
      ),
    );

    if (onTap == null) {
      return row;
    }
    return InkWell(onTap: onTap, child: row);
  }
}
