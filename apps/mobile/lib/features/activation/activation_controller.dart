import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/auth/auth_repository.dart';
import '../../core/network/error_copy.dart';
import '../../core/network/network_guard.dart';
import '../../core/widgets/submission_state.dart';

class ActivationController extends Notifier<SubmissionState> {
  @override
  SubmissionState build() => const SubmissionIdle();

  Future<void> activate({
    required String token,
    required String newPassword,
  }) async {
    state = const SubmissionInProgress();
    try {
      await runGuarded(
        ref,
        () => ref
            .read(authRepositoryProvider)
            .activateAccount(token: token, newPassword: newPassword),
      );
      state = const SubmissionSuccess();
    } catch (error) {
      state = SubmissionFailure(userFacingErrorMessage(error));
    }
  }
}

final activationControllerProvider =
    NotifierProvider<ActivationController, SubmissionState>(
      ActivationController.new,
    );
