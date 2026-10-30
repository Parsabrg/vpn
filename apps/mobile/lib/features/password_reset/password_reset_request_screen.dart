import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/routing/route_paths.dart';
import '../../core/theme/color_tokens.dart';
import '../../core/widgets/panel/auth_scaffold.dart';
import '../../core/widgets/panel/panel_cta.dart';
import '../../core/widgets/submission_state.dart';
import '../../l10n/app_localizations.dart';
import 'password_reset_controller.dart';

class PasswordResetRequestScreen extends ConsumerStatefulWidget {
  const PasswordResetRequestScreen({super.key});

  @override
  ConsumerState<PasswordResetRequestScreen> createState() =>
      _PasswordResetRequestScreenState();
}

class _PasswordResetRequestScreenState
    extends ConsumerState<PasswordResetRequestScreen> {
  final GlobalKey<FormState> _formKey = GlobalKey<FormState>();
  final TextEditingController _identifierController = TextEditingController();

  @override
  void dispose() {
    _identifierController.dispose();
    super.dispose();
  }

  void _submit() {
    if (!_formKey.currentState!.validate()) {
      return;
    }
    ref
        .read(passwordResetRequestControllerProvider.notifier)
        .submit(_identifierController.text.trim());
  }

  @override
  Widget build(BuildContext context) {
    final AppText text = AppText.of(context);
    final SubmissionState state = ref.watch(
      passwordResetRequestControllerProvider,
    );

    if (state is SubmissionSuccess) {
      // Same neutral copy whether or not the account exists -- the screen
      // must not become an oracle for which emails are registered.
      return AuthScaffold(
        title: text.checkEmailTitle,
        subline: text.checkEmailSubline,
        fields: <Widget>[
          Icon(
            Icons.mark_email_read_outlined,
            size: 32,
            color: context.palette.blueText,
          ),
        ],
        action: PanelCta(
          label: text.haveACode,
          style: CtaStyle.secondary,
          onPressed: () => context.go(RoutePaths.passwordResetConfirm),
        ),
        footer: Center(
          child: TextButton(
            onPressed: () => context.go(RoutePaths.signIn),
            child: Text(text.backToSignIn),
          ),
        ),
      );
    }

    final bool inProgress = state is SubmissionInProgress;

    return Form(
      key: _formKey,
      child: AuthScaffold(
        title: text.resetPasswordTitle,
        subline: text.resetPasswordSubline,
        errorMessage: state is SubmissionFailure ? state.message : null,
        fields: <Widget>[
          TextFormField(
            controller: _identifierController,
            decoration: InputDecoration(hintText: text.fieldEmailOrUsername),
            validator: (String? value) =>
                (value == null || value.trim().length < 3)
                ? text.validateEmailOrUsername
                : null,
          ),
        ],
        action: PanelCta(
          label: inProgress ? text.sending : text.sendResetInstructions,
          onPressed: inProgress ? null : _submit,
        ),
      ),
    );
  }
}
