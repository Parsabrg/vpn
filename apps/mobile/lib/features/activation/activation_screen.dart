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
import 'activation_controller.dart';

class ActivationScreen extends ConsumerStatefulWidget {
  const ActivationScreen({super.key});

  @override
  ConsumerState<ActivationScreen> createState() => _ActivationScreenState();
}

class _ActivationScreenState extends ConsumerState<ActivationScreen> {
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
        .read(activationControllerProvider.notifier)
        .activate(
          token: _tokenController.text.trim(),
          newPassword: _passwordController.text,
        );
  }

  @override
  Widget build(BuildContext context) {
    final SubmissionState state = ref.watch(activationControllerProvider);

    ref.listen<SubmissionState>(activationControllerProvider, (
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
        title: text.activateTitle,
        subline: text.codeFromEmail,
        errorMessage: state is SubmissionFailure ? state.message : null,
        fields: <Widget>[
          TextFormField(
            controller: _tokenController,
            // Mono with a little tracking: this is a long opaque string
            // someone is checking character by character against an email.
            style: context.type.rowValue.copyWith(letterSpacing: 1),
            decoration: InputDecoration(hintText: text.fieldActivationCode),
            validator: (String? value) =>
                (value == null || value.trim().length < 10)
                ? text.validateActivationCode
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
          label: inProgress ? text.activating : text.activateAction,
          onPressed: inProgress ? null : _submit,
        ),
      ),
    );
  }
}
