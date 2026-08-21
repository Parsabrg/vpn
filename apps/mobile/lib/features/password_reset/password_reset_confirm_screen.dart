import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/routing/route_paths.dart';
import '../../core/widgets/password_field.dart';
import '../../core/widgets/submission_state.dart';
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

    return Scaffold(
      appBar: AppBar(
        leading: BackButton(
          onPressed: () => context.go(RoutePaths.passwordReset),
        ),
        title: const Text('Set a new password'),
      ),
      body: SafeArea(
        child: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 480),
            child: Padding(
              padding: const EdgeInsets.all(24),
              child: Form(
                key: _formKey,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  mainAxisSize: MainAxisSize.min,
                  children: <Widget>[
                    Text(
                      'Paste the reset code from your email and choose a '
                      'new password.',
                      style: Theme.of(context).textTheme.bodyMedium,
                    ),
                    const SizedBox(height: 24),
                    TextFormField(
                      controller: _tokenController,
                      decoration: const InputDecoration(
                        labelText: 'Reset code',
                      ),
                      validator: (String? value) =>
                          (value == null || value.trim().length < 10)
                          ? 'Enter the reset code from your email'
                          : null,
                    ),
                    const SizedBox(height: 16),
                    PasswordField(
                      controller: _passwordController,
                      labelText: 'New password',
                      autofillHints: const <String>[
                        AutofillHints.newPassword,
                      ],
                      validator: (String? value) =>
                          (value == null || value.length < 12)
                          ? 'Use at least 12 characters'
                          : null,
                    ),
                    if (state is SubmissionFailure) ...<Widget>[
                      const SizedBox(height: 16),
                      Semantics(
                        liveRegion: true,
                        child: Text(
                          state.message,
                          style: TextStyle(
                            color: Theme.of(context).colorScheme.error,
                          ),
                        ),
                      ),
                    ],
                    const SizedBox(height: 24),
                    FilledButton(
                      onPressed: state is SubmissionInProgress
                          ? null
                          : _submit,
                      child: state is SubmissionInProgress
                          ? const SizedBox(
                              height: 20,
                              width: 20,
                              child: CircularProgressIndicator(
                                strokeWidth: 2,
                              ),
                            )
                          : const Text('Set password'),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}
