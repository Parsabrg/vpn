import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/routing/route_paths.dart';
import '../../core/theme/type_scale.dart';
import '../../core/widgets/panel/auth_scaffold.dart';
import '../../core/widgets/panel/panel_cta.dart';
import '../../core/widgets/password_field.dart';
import '../../core/widgets/submission_state.dart';
import '../../l10n/app_localizations.dart';
import 'password_reset_controller.dart';

class PasswordResetConfirmScreen extends ConsumerStatefulWidget {
  const PasswordResetConfirmScreen({super.key});

  @override
  ConsumerState<PasswordResetConfirmScreen> createState() =>
      _PasswordResetConfirmScreenState();
}

class _PasswordResetConfirmScreenState
    extends ConsumerState<PasswordResetConfirmScreen> {
  final GlobalKey<FormState> _formKey = GlobalKey<FormState>();
  final TextEditingController _tokenController = TextEditingController();
  final TextEditingController _passwordController = TextEditingController();

  @override
  void dispose() {
    _tokenController.dispose();
    _passwordController.dispose();
    super.dispose();
  }

  void _submit() {
    if (!_formKey.currentState!.validate()) {
      return;
    }
    ref
        .read(passwordResetConfirmControllerProvider.notifier)
        .confirm(
          token: _tokenController.text.trim(),
          newPassword: _passwordController.text,
        );
  }

  @override
  Widget build(BuildContext context) {
    final SubmissionState state = ref.watch(
      passwordResetConfirmControllerProvider,
    );

    ref.listen<SubmissionState>(passwordResetConfirmControllerProvider, (
      SubmissionState? previous,
      SubmissionState next,
    ) {
      if (next is SubmissionSuccess) {
        context.go(RoutePaths.signIn);
      }
    });

    final AppText text = AppText.of(context);
    final bool inProgress = state is SubmissionInProgress;

    return Form(
      key: _formKey,
      child: AuthScaffold(
        title: text.newPasswordTitle,
        subline: text.codeFromEmail,
        errorMessage: state is SubmissionFailure ? state.message : null,
        fields: <Widget>[
          TextFormField(
            controller: _tokenController,
            style: context.type.rowValue.copyWith(letterSpacing: 1),
            decoration: InputDecoration(hintText: text.fieldResetCode),
            validator: (String? value) =>
                (value == null || value.trim().length < 10)
                ? text.validateResetCode
                : null,
          ),
          PasswordField(
            controller: _passwordController,
            labelText: text.fieldNewPassword,
            autofillHints: const <String>[AutofillHints.newPassword],
            onChanged: (_) => setState(() {}),
            validator: (String? value) => (value == null || value.length < 12)
                ? text.validateNewPassword
                : null,
          ),
        ],
        aboveAction: PasswordRequirementNote(
          satisfied: _passwordController.text.length >= 12,
          text: text.passwordMinimum,
        ),
        action: PanelCta(
          label: inProgress ? text.settingPassword : text.setPassword,
          onPressed: inProgress ? null : _submit,
        ),
      ),
    );
  }
}
