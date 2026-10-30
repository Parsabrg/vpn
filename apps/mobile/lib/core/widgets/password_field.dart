import 'package:flutter/material.dart';

import '../../l10n/app_localizations.dart';

/// A password [TextFormField] with a visibility toggle. The toggle is
/// icon-only, so it carries an explicit [Semantics] label reflecting its
/// current action -- screen readers must hear "Show password" / "Hide
/// password," not silence.
class PasswordField extends StatefulWidget {
  const PasswordField({
    required this.controller,
    required this.labelText,
    this.validator,
    this.autofillHints,
    this.onChanged,
    super.key,
  });

  final TextEditingController controller;
  final String labelText;
  final String? Function(String?)? validator;
  final Iterable<String>? autofillHints;

  /// Fires on every keystroke. The redesign shows a requirement note that
  /// resolves as you type, and a note that only updated on submit would be
  /// telling you what you already found out.
  final ValueChanged<String>? onChanged;

  @override
  State<PasswordField> createState() => _PasswordFieldState();
}

class _PasswordFieldState extends State<PasswordField> {
  bool _obscured = true;

  @override
  Widget build(BuildContext context) {
    final AppText text = AppText.of(context);
    final String toggleLabel = _obscured
        ? text.showPassword
        : text.hidePassword;
    return TextFormField(
      controller: widget.controller,
      obscureText: _obscured,
      autofillHints: widget.autofillHints,
      validator: widget.validator,
      onChanged: widget.onChanged,
      decoration: InputDecoration(
        labelText: widget.labelText,
        suffixIcon: Semantics(
          label: toggleLabel,
          button: true,
          child: IconButton(
            tooltip: toggleLabel,
            // The icon shows the field's state -- crossed out while the
            // password is hidden -- and the label says what a tap does. The
            // other way round read as backwards: a crossed-out eye beside a
            // password you could read.
            icon: Icon(
              _obscured
                  ? Icons.visibility_off_outlined
                  : Icons.visibility_outlined,
            ),
            onPressed: () => setState(() => _obscured = !_obscured),
          ),
        ),
      ),
    );
  }
}
