import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/auth/auth_repository.dart';
import '../../core/network/error_copy.dart';
import '../../core/network/network_guard.dart';
import '../../core/widgets/submission_state.dart';

class PasswordResetRequestController extends Notifier<SubmissionState> {
  @override
  SubmissionState build() => const SubmissionIdle();

  Future<void> submit(String identifier) async {
    state = const SubmissionInProgress();
    try {
      await runGuarded(
        ref,
        () => ref.read(authRepositoryProvider).requestPasswordReset(identifier),
      );
      state = const SubmissionSuccess();
    } catch (error) {
      state = SubmissionFailure(userFacingErrorMessage(error));
    }
  }
}

final passwordResetRequestControllerProvider =
    NotifierProvider<PasswordResetRequestController, SubmissionState>(
      PasswordResetRequestController.new,
    );

class PasswordResetConfirmController extends Notifier<SubmissionState> {
  @override
  SubmissionState build() => const SubmissionIdle();

  Future<void> confirm({
    required String token,
    required String newPassword,
  }) async {
    state = const SubmissionInProgress();
    try {
      await runGuarded(
        ref,
        () => ref
            .read(authRepositoryProvider)
            .confirmPasswordReset(token: token, newPassword: newPassword),
      );
      state = const SubmissionSuccess();
    } catch (error) {
      state = SubmissionFailure(userFacingErrorMessage(error));
    }
  }
}

final passwordResetConfirmControllerProvider =
    NotifierProvider<PasswordResetConfirmController, SubmissionState>(
      PasswordResetConfirmController.new,
    );
