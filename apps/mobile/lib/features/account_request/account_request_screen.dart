import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/routing/route_paths.dart';
import '../../core/theme/color_tokens.dart';
import '../../core/widgets/panel/auth_scaffold.dart';
import '../../core/widgets/panel/panel_cta.dart';
import '../../core/widgets/submission_state.dart';
import '../../l10n/app_localizations.dart';
import 'account_request_controller.dart';

class AccountRequestScreen extends ConsumerStatefulWidget {
  const AccountRequestScreen({super.key});

  @override
  ConsumerState<AccountRequestScreen> createState() =>
      _AccountRequestScreenState();
}

class _AccountRequestScreenState extends ConsumerState<AccountRequestScreen> {
  final GlobalKey<FormState> _formKey = GlobalKey<FormState>();
  final TextEditingController _emailController = TextEditingController();
  final TextEditingController _usernameController = TextEditingController();

  @override
  void dispose() {
    _emailController.dispose();
    _usernameController.dispose();
    super.dispose();
  }

  void _submit() {
    if (!_formKey.currentState!.validate()) {
      return;
    }
    final String username = _usernameController.text.trim();
    ref
        .read(accountRequestControllerProvider.notifier)
        .submit(
          email: _emailController.text.trim(),
          username: username.isEmpty ? null : username,
        );
  }

  @override
  Widget build(BuildContext context) {
    final SubmissionState state = ref.watch(accountRequestControllerProvider);

    return switch (state) {
      SubmissionSuccess() => const _RequestSubmitted(),
      _ => _RequestForm(
        formKey: _formKey,
        emailController: _emailController,
        usernameController: _usernameController,
        submitting: state is SubmissionInProgress,
        errorMessage: state is SubmissionFailure ? state.message : null,
        onSubmit: _submit,
      ),
    };
  }
}

class _RequestForm extends StatelessWidget {
  const _RequestForm({
    required this.formKey,
    required this.emailController,
    required this.usernameController,
    required this.submitting,
    required this.errorMessage,
    required this.onSubmit,
  });

  final GlobalKey<FormState> formKey;
  final TextEditingController emailController;
  final TextEditingController usernameController;
  final bool submitting;
  final String? errorMessage;
  final VoidCallback onSubmit;

  @override
  Widget build(BuildContext context) {
    final AppText text = AppText.of(context);
    return Form(
      key: formKey,
      child: AuthScaffold(
        title: text.requestAccessTitle,
        subline: text.requestAccessSubline,
        errorMessage: errorMessage,
        fields: <Widget>[
          TextFormField(
            controller: emailController,
            keyboardType: TextInputType.emailAddress,
            // No autofill: with an email hint Google Password Manager offered
            // the saved sign-in password over a form that has none.
            autofillHints: null,
            decoration: InputDecoration(hintText: text.fieldEmail),
            validator: (String? value) =>
                looksLikeEmail(value) ? null : text.validateEmail,
          ),
          TextFormField(
            controller: usernameController,
            autofillHints: null,
            decoration: InputDecoration(hintText: text.fieldUsernameOptional),
          ),
        ],
        action: PanelCta(
          label: submitting ? text.sending : text.sendRequest,
          onPressed: submitting ? null : onSubmit,
        ),
      ),
    );
  }
}

/// Sent. This used to be a bare icon and sentence with no way off it but the
/// system Back gesture; it now has the same two exits as a sent password
/// reset: the activation code the email carries, and back to sign-in.
class _RequestSubmitted extends StatelessWidget {
  const _RequestSubmitted();

  @override
  Widget build(BuildContext context) {
    final AppText text = AppText.of(context);
    return AuthScaffold(
      title: text.requestAccessTitle,
      subline: text.requestSubmitted,
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
        onPressed: () => context.go(RoutePaths.activate),
      ),
      footer: Center(
        child: TextButton(
          onPressed: () => context.go(RoutePaths.signIn),
          child: Text(text.backToSignIn),
        ),
      ),
    );
  }
}

/// Checked here because the server answers every request the same way, so
/// it cannot say "that address is mistyped": a typo was accepted, and the
/// person waited for an email that could never come (2026-10-29).
bool looksLikeEmail(String? value) =>
    RegExp(r'^[^@\s]+@[^@\s]+\.[^@\s]+$').hasMatch(value?.trim() ?? '');
