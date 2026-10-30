import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/free/free_mode.dart';
import '../../core/routing/route_paths.dart';
import '../../core/theme/type_scale.dart';
import '../../core/widgets/panel/auth_scaffold.dart';
import '../../core/widgets/panel/panel_cta.dart';
import '../../core/widgets/submission_state.dart';
import '../../l10n/app_localizations.dart';
import 'pairing_controller.dart';
import 'qr_scan.dart';

/// First launch of a generic build: which deployment is this app for?
class PairingScreen extends ConsumerStatefulWidget {
  const PairingScreen({super.key});

  @override
  ConsumerState<PairingScreen> createState() => _PairingScreenState();
}

class _PairingScreenState extends ConsumerState<PairingScreen> {
  final GlobalKey<FormState> _formKey = GlobalKey<FormState>();
  final TextEditingController _linkController = TextEditingController();

  @override
  void dispose() {
    _linkController.dispose();
    super.dispose();
  }

  void _submit() {
    if (!_formKey.currentState!.validate()) {
      return;
    }
    ref.read(pairingControllerProvider.notifier).pair(_linkController.text);
  }

  /// A scanned code goes through the same [PairingController.pair] as a
  /// pasted link, so the pin and deployment checks stay in one place.
  Future<void> _scan() async {
    final String? scanned = await ref.read(qrScanProvider)(context);
    if (!mounted || scanned == null) {
      return;
    }
    _linkController.text = scanned;
    ref.read(pairingControllerProvider.notifier).pair(scanned);
  }

  @override
  Widget build(BuildContext context) {
    final SubmissionState state = ref.watch(pairingControllerProvider);
    ref.listen<SubmissionState>(pairingControllerProvider, (
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
        title: text.pairTitle,
        subline: text.pairSubline,
        errorMessage: state is SubmissionFailure ? state.message : null,
        fields: <Widget>[
          TextFormField(
            controller: _linkController,
            keyboardType: TextInputType.url,
            autocorrect: false,
            enableSuggestions: false,
            maxLines: 3,
            minLines: 1,
            style: context.type.rowValue,
            decoration: InputDecoration(hintText: text.pairField),
            validator: (String? value) =>
                (value == null || value.trim().isEmpty)
                ? text.pairErrorMalformed
                : null,
            onFieldSubmitted: (_) => _submit(),
          ),
          if (qrScanAvailable)
            Align(
              alignment: AlignmentDirectional.centerStart,
              child: TextButton.icon(
                onPressed: inProgress ? null : _scan,
                icon: const Icon(Icons.qr_code_scanner),
                label: Text(text.pairScan),
              ),
            ),
        ],
        action: PanelCta(
          label: inProgress ? text.pairInProgress : text.pairAction,
          onPressed: inProgress ? null : _submit,
        ),
        // The other way in: no server at all.
        footer: TextButton(
          onPressed: inProgress
              ? null
              : () => ref.read(freeModeProvider.notifier).enter(),
          child: Text(text.freeEnter),
        ),
      ),
    );
  }
}
