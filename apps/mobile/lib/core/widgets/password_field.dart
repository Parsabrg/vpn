import 'package:flutter/material.dart';

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
    super.key,
  });

  final TextEditingController controller;
  final String labelText;
  final String? Function(String?)? validator;
  final Iterable<String>? autofillHints;

  @override
  State<PasswordField> createState() => _PasswordFieldState();
}

class _PasswordFieldState extends State<PasswordField> {
  bool _obscured = true;

  @override
  Widget build(BuildContext context) {
    final String toggleLabel = _obscured ? 'Show password' : 'Hide password';
    return TextFormField(
      controller: widget.controller,
      obscureText: _obscured,
      autofillHints: widget.autofillHints,
      validator: widget.validator,
      decoration: InputDecoration(
        labelText: widget.labelText,
        suffixIcon: Semantics(
          label: toggleLabel,
          button: true,
          child: IconButton(
            tooltip: toggleLabel,
            icon: Icon(
              _obscured
                  ? Icons.visibility_outlined
                  : Icons.visibility_off_outlined,
            ),
            onPressed: () => setState(() => _obscured = !_obscured),
          ),
        ),
      ),
    );
  }
}
