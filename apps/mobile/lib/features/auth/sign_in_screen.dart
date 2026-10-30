import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/app_info.dart';
import '../../core/auth/auth_notifier.dart';
import '../../core/auth/auth_state.dart';
import '../../core/free/free_mode.dart';
import '../../core/network/error_copy.dart';
import '../../core/pairing/pairing.dart';
import '../../core/pairing/pairing_providers.dart';
import '../../core/routing/route_paths.dart';
import '../../core/settings/locale_controller.dart';
import '../../core/theme/color_tokens.dart';
import '../../core/theme/type_scale.dart';
import '../../core/widgets/panel/auth_scaffold.dart';
import '../../core/widgets/panel/panel_cta.dart';
import '../../core/widgets/password_field.dart';
import '../../l10n/app_localizations.dart';

class SignInScreen extends ConsumerStatefulWidget {
  const SignInScreen({super.key});

  @override
  ConsumerState<SignInScreen> createState() => _SignInScreenState();
}

class _SignInScreenState extends ConsumerState<SignInScreen> {
  final GlobalKey<FormState> _formKey = GlobalKey<FormState>();
  final TextEditingController _identifierController = TextEditingController();
  final TextEditingController _passwordController = TextEditingController();

  bool _submitting = false;
  String? _errorMessage;

  @override
  void dispose() {
    _identifierController.dispose();
    _passwordController.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (!_formKey.currentState!.validate()) {
      return;
    }
    setState(() {
      _submitting = true;
      _errorMessage = null;
    });
    try {
      await ref
          .read(authNotifierProvider.notifier)
          .login(
            identifier: _identifierController.text.trim(),
            password: _passwordController.text,
            deviceName: currentDeviceName,
            platform: currentDevicePlatform,
            clientVersion: kClientVersion,
          );
    } catch (error) {
      if (mounted) {
        setState(
          () => _errorMessage = userFacingErrorMessage(
            error,
            ref.read(appTextProvider),
          ),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _submitting = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final AppText text = AppText.of(context);
    final AuthState authState = ref.watch(authNotifierProvider);
    final bool sessionExpired = authState is AuthSessionExpired;
    final Pairing? pairing = ref.watch(pairingProvider);

    return Form(
      key: _formKey,
      child: AuthScaffold(
        title: text.signInTitle,
        subline: sessionExpired ? text.signInSessionEnded : text.signInSubline,
        errorMessage: _errorMessage,
        fields: <Widget>[
          TextFormField(
            controller: _identifierController,
            autofillHints: const <String>[
              AutofillHints.username,
              AutofillHints.email,
            ],
            decoration: InputDecoration(hintText: text.fieldEmailOrUsername),
            validator: (String? value) =>
                (value == null || value.trim().isEmpty)
                ? text.validateEmailOrUsername
                : null,
          ),
          PasswordField(
            controller: _passwordController,
            labelText: text.fieldPassword,
            autofillHints: const <String>[AutofillHints.password],
            validator: (String? value) =>
                (value == null || value.isEmpty) ? text.validatePassword : null,
          ),
        ],
        aboveAction: Align(
          alignment: AlignmentDirectional.centerEnd,
          child: TextButton(
            onPressed: () => context.push(RoutePaths.passwordReset),
            child: Text(text.forgotPassword),
          ),
        ),
        action: PanelCta(
          label: _submitting ? text.signingIn : text.continueAction,
          onPressed: _submitting ? null : _submit,
        ),
        // One row, not two stacked full-width buttons. These are the two ways
        // in for someone who cannot sign in yet, and neither deserves the
        // weight of a button as wide as the primary action.
        footer: Column(
          mainAxisSize: MainAxisSize.min,
          children: <Widget>[
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: <Widget>[
                TextButton(
                  onPressed: () => context.push(RoutePaths.accountRequest),
                  child: Text(text.requestAccess),
                ),
                Text(
                  '·',
                  style: context.type.listMeta.copyWith(
                    color: context.palette.textMuted,
                  ),
                ),
                // Without this the activation screen is unreachable: the route
                // exists and is registered, but nothing navigated to it, so an
                // approved user holding an activation code had no way to spend it
                // and was left at a sign-in form asking for a password they had
                // never been able to set.
                TextButton(
                  onPressed: () => context.push(RoutePaths.activate),
                  child: Text(text.haveACode),
                ),
              ],
            ),
            TextButton(
              onPressed: () => ref.read(freeModeProvider.notifier).enter(),
              child: Text(text.freeEnter),
            ),
            if (pairing?.deploymentName != null)
              // Which deployment this is, checked against what the person
              // expects before they type a password into it.
              Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: <Widget>[
                  Flexible(
                    child: Text(
                      text.pairedServer(pairing!.deploymentName!),
                      overflow: TextOverflow.ellipsis,
                      style: context.type.listMeta.copyWith(
                        color: context.palette.textMuted,
                      ),
                    ),
                  ),
                  TextButton(
                    onPressed: () =>
                        ref.read(pairingProvider.notifier).forget(),
                    child: Text(text.changeServer),
                  ),
                ],
              ),
          ],
        ),
      ),
    );
  }
}
