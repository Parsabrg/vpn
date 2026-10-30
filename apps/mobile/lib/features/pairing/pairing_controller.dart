import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/pairing/pairing.dart';
import '../../core/pairing/pairing_providers.dart';
import '../../core/settings/locale_controller.dart';
import '../../core/widgets/submission_state.dart';
import '../../l10n/app_localizations.dart';

class PairingController extends Notifier<SubmissionState> {
  @override
  SubmissionState build() => const SubmissionIdle();

  Future<void> pair(String input) async {
    state = const SubmissionInProgress();
    final AppText text = ref.read(appTextProvider);
    try {
      // Plain http only in a debug build, for a development API on this
      // machine; never in a release, where credentials travel over it.
      final PairingLink link = PairingLink.parse(
        input,
        allowPlainHttp: !kReleaseMode,
      );
      final Pairing pairing = await ref.read(pairingClientProvider).pair(link);
      await ref.read(pairingProvider.notifier).adopt(pairing);
      state = const SubmissionSuccess();
    } on PairingException catch (error) {
      state = SubmissionFailure(pairingFailureMessage(error.failure, text));
    }
  }
}

final pairingControllerProvider =
    NotifierProvider<PairingController, SubmissionState>(PairingController.new);

String pairingFailureMessage(PairingFailure failure, AppText text) =>
    switch (failure) {
      PairingFailure.malformed => text.pairErrorMalformed,
      PairingFailure.notHttps => text.pairErrorNotHttps,
      PairingFailure.unsupportedVersion => text.pairErrorVersion,
      PairingFailure.unreachable => text.pairErrorUnreachable,
      PairingFailure.certificateMismatch => text.pairErrorCertificate,
      PairingFailure.deploymentMismatch => text.pairErrorDeployment,
      PairingFailure.needsLink => text.pairErrorNeedsLink,
    };
