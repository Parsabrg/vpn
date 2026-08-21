import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/routing/route_paths.dart';
import '../../core/widgets/submission_state.dart';
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

    return Scaffold(
      appBar: AppBar(
        leading: BackButton(onPressed: () => context.go(RoutePaths.signIn)),
        title: const Text('Request access'),
      ),
      body: SafeArea(
        child: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 480),
            child: Padding(
              padding: const EdgeInsets.all(24),
              child: switch (state) {
                SubmissionSuccess() => const _RequestSubmitted(),
                _ => _RequestForm(
                  formKey: _formKey,
                  emailController: _emailController,
                  usernameController: _usernameController,
                  submitting: state is SubmissionInProgress,
                  errorMessage: state is SubmissionFailure
                      ? state.message
                      : null,
                  onSubmit: _submit,
                ),
              },
            ),
          ),
        ),
      ),
    );
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
    return Form(
      key: formKey,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        mainAxisSize: MainAxisSize.min,
        children: <Widget>[
          Text(
            'Nebula VPN is invite-only. Submit your email and an '
            'administrator will review your request.',
            style: Theme.of(context).textTheme.bodyMedium,
          ),
          const SizedBox(height: 24),
          TextFormField(
            controller: emailController,
            keyboardType: TextInputType.emailAddress,
            autofillHints: const <String>[AutofillHints.email],
            decoration: const InputDecoration(labelText: 'Email'),
            validator: (String? value) =>
                (value == null || value.trim().length < 3)
                ? 'Enter a valid email'
                : null,
          ),
          const SizedBox(height: 16),
          TextFormField(
            controller: usernameController,
            decoration: const InputDecoration(
              labelText: 'Username (optional)',
            ),
          ),
          if (errorMessage != null) ...<Widget>[
            const SizedBox(height: 16),
            Semantics(
              liveRegion: true,
              child: Text(
                errorMessage!,
                style: TextStyle(color: Theme.of(context).colorScheme.error),
              ),
            ),
          ],
          const SizedBox(height: 24),
          FilledButton(
            onPressed: submitting ? null : onSubmit,
            child: submitting
                ? const SizedBox(
                    height: 20,
                    width: 20,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Text('Submit request'),
          ),
        ],
      ),
    );
  }
}

class _RequestSubmitted extends StatelessWidget {
  const _RequestSubmitted();

  @override
  Widget build(BuildContext context) {
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: <Widget>[
        Icon(
          Icons.mark_email_read_outlined,
          size: 48,
          color: Theme.of(context).colorScheme.primary,
        ),
        const SizedBox(height: 16),
        Text(
          'If that email is eligible, you will receive activation '
          'instructions shortly.',
          textAlign: TextAlign.center,
          style: Theme.of(context).textTheme.bodyLarge,
        ),
      ],
    );
  }
}
