import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/auth/auth_notifier.dart';
import '../../core/auth/auth_state.dart';
import '../../core/auth/user_principal.dart';

class AccountScreen extends ConsumerWidget {
  const AccountScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final AuthState authState = ref.watch(authNotifierProvider);
    final UserPrincipal? me = authState is AuthAuthenticated
        ? authState.me
        : null;

    return Scaffold(
      appBar: AppBar(title: const Text('Account')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: <Widget>[
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: me == null
                  ? const _AccountLoading()
                  : _AccountDetails(me: me),
            ),
          ),
          const SizedBox(height: 24),
          FilledButton.tonalIcon(
            onPressed: () =>
                ref.read(authNotifierProvider.notifier).logout(),
            icon: const Icon(Icons.logout),
            label: const Semantics(
              label: 'Sign out of your Nebula VPN account',
              child: Text('Sign out'),
            ),
          ),
        ],
      ),
    );
  }
}

class _AccountLoading extends StatelessWidget {
  const _AccountLoading();

  @override
  Widget build(BuildContext context) {
    return const Row(
      children: <Widget>[
        SizedBox(
          height: 16,
          width: 16,
          child: CircularProgressIndicator(strokeWidth: 2),
        ),
        SizedBox(width: 12),
        Text('Loading account details...'),
      ],
    );
  }
}

class _AccountDetails extends StatelessWidget {
  const _AccountDetails({required this.me});

  final UserPrincipal me;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: <Widget>[
        _DetailRow(label: 'User ID', value: me.userId),
        _DetailRow(label: 'Session ID', value: me.sessionId),
        _DetailRow(label: 'This device', value: me.deviceId),
      ],
    );
  }
}

class _DetailRow extends StatelessWidget {
  const _DetailRow({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          Text(label, style: Theme.of(context).textTheme.labelMedium),
          Text(value, style: Theme.of(context).textTheme.bodyMedium),
        ],
      ),
    );
  }
}
