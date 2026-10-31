import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/account/account_repository.dart';
import '../../core/auth/auth_notifier.dart';
import '../../core/network/api_exception.dart';
import '../../core/network/error_copy.dart';
import '../../core/settings/locale_controller.dart';
import '../../core/theme/color_tokens.dart';
import '../../core/theme/type_scale.dart';
import '../../core/widgets/panel/auth_scaffold.dart';
import '../../core/widgets/panel/panel_cta.dart';
import '../../core/widgets/password_field.dart';
import '../../l10n/app_localizations.dart';
import '../devices/devices_controller.dart';

/// What to show for a refused password change or deletion. The server
/// answers 403 for a wrong password -- not 401, which would sign out.
String _refusal(Object error, AppText text) =>
    error is NebulaApiException &&
        error.statusCode == 403 &&
        error.detail == 'password_not_accepted'
    ? text.passwordNotAccepted
    : userFacingErrorMessage(error, text);

/// The frame both screens share: a back arrow, a title, the fields, and the
/// action at the thumb.
class _Frame extends StatelessWidget {
  const _Frame({
    required this.title,
    required this.fields,
    required this.action,
  });

  final String title;
  final List<Widget> fields;
  final Widget action;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: context.palette.bg,
      appBar: AppBar(
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          onPressed: () => Navigator.of(context).maybePop(),
        ),
        title: Text(title),
      ),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: <Widget>[
              Expanded(
                child: ListView(
                  children: <Widget>[const SizedBox(height: 12), ...fields],
                ),
              ),
              Padding(
                padding: const EdgeInsets.only(bottom: 16),
                child: action,
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class ChangePasswordScreen extends ConsumerStatefulWidget {
  const ChangePasswordScreen({super.key});

  @override
  ConsumerState<ChangePasswordScreen> createState() =>
      _ChangePasswordScreenState();
}

class _ChangePasswordScreenState extends ConsumerState<ChangePasswordScreen> {
  final GlobalKey<FormState> _formKey = GlobalKey<FormState>();
  final TextEditingController _current = TextEditingController();
  final TextEditingController _next = TextEditingController();
  bool _busy = false;
  String? _error;

  @override
  void dispose() {
    _current.dispose();
    _next.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (!_formKey.currentState!.validate()) {
      return;
    }
    final AppText text = ref.read(appTextProvider);
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await ref
          .read(accountRepositoryProvider)
          .changePassword(
            currentPassword: _current.text,
            newPassword: _next.text,
          );
      if (!mounted) {
        return;
      }
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(text.passwordChanged)));
      context.pop();
    } catch (error) {
      if (mounted) {
        setState(() => _error = _refusal(error, text));
      }
    } finally {
      if (mounted) {
        setState(() => _busy = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final AppText text = AppText.of(context);
    return Form(
      key: _formKey,
      child: _Frame(
        title: text.changePasswordTitle,
        fields: <Widget>[
          Text(
            text.changePasswordIntro,
            style: context.type.listMeta.copyWith(
              color: context.palette.textMuted,
            ),
          ),
          const SizedBox(height: 20),
          PasswordField(
            controller: _current,
            labelText: text.fieldCurrentPassword,
            autofillHints: const <String>[AutofillHints.password],
            validator: (String? value) =>
                (value == null || value.isEmpty) ? text.validatePassword : null,
          ),
          const SizedBox(height: 12),
          PasswordField(
            controller: _next,
            labelText: text.fieldNewPassword,
            autofillHints: const <String>[AutofillHints.newPassword],
            onChanged: (_) => setState(() {}),
            validator: (String? value) => (value == null || value.length < 12)
                ? text.validateNewPassword
                : null,
          ),
          const SizedBox(height: 8),
          PasswordRequirementNote(
            satisfied: _next.text.length >= 12,
            text: text.passwordMinimum,
          ),
          if (_error != null) ...<Widget>[
            const SizedBox(height: 16),
            Text(
              _error!,
              style: context.type.listMeta.copyWith(
                color: context.palette.redText,
              ),
            ),
          ],
        ],
        action: PanelCta(
          label: _busy ? text.changingPassword : text.changePasswordAction,
          onPressed: _busy ? null : _submit,
        ),
      ),
    );
  }
}

class DeleteAccountScreen extends ConsumerStatefulWidget {
  const DeleteAccountScreen({super.key});

  @override
  ConsumerState<DeleteAccountScreen> createState() =>
      _DeleteAccountScreenState();
}

class _DeleteAccountScreenState extends ConsumerState<DeleteAccountScreen> {
  final GlobalKey<FormState> _formKey = GlobalKey<FormState>();
  final TextEditingController _password = TextEditingController();
  bool _busy = false;
  String? _error;

  @override
  void dispose() {
    _password.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (!_formKey.currentState!.validate()) {
      return;
    }
    final AppText text = ref.read(appTextProvider);
    final ScaffoldMessengerState messenger = ScaffoldMessenger.of(context);
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      // Asked first: a mistyped password must not cost the tunnel.
      await ref.read(accountRepositoryProvider).deleteAccount(_password.text);
    } catch (error) {
      if (mounted) {
        setState(() {
          _busy = false;
          _error = _refusal(error, text);
        });
      }
      return;
    }
    // Gone on the server, credentials included: stop the tunnel here without
    // asking it, forget the session, and the router shows sign-in.
    messenger.showSnackBar(SnackBar(content: Text(text.accountDeleted)));
    await ref.read(devicesControllerProvider.notifier).endAfterSessionLost();
    await ref.read(authNotifierProvider.notifier).logout();
  }

  @override
  Widget build(BuildContext context) {
    final AppText text = AppText.of(context);
    final NebulaPalette palette = context.palette;
    return Form(
      key: _formKey,
      child: _Frame(
        title: text.deleteAccountTitle,
        fields: <Widget>[
          Text(
            text.deleteAccountIntro,
            style: context.type.listMeta.copyWith(color: palette.redText),
          ),
          const SizedBox(height: 12),
          Text(
            text.deleteAccountKept,
            style: context.type.listMeta.copyWith(color: palette.textMuted),
          ),
          const SizedBox(height: 20),
          PasswordField(
            controller: _password,
            labelText: text.fieldPassword,
            autofillHints: const <String>[AutofillHints.password],
            validator: (String? value) =>
                (value == null || value.isEmpty) ? text.validatePassword : null,
          ),
          if (_error != null) ...<Widget>[
            const SizedBox(height: 16),
            Text(
              _error!,
              style: context.type.listMeta.copyWith(color: palette.redText),
            ),
          ],
        ],
        action: PanelCta(
          label: _busy ? text.deletingAccount : text.deleteAccountAction,
          style: CtaStyle.secondary,
          onPressed: _busy ? null : _submit,
        ),
      ),
    );
  }
}
