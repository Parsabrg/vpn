import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/auth/auth_repository.dart';
import '../../core/network/error_copy.dart';
import '../../core/network/network_guard.dart';
import '../../core/widgets/submission_state.dart';

class AccountRequestController extends Notifier<SubmissionState> {
  @override
  SubmissionState build() => const SubmissionIdle();

  Future<void> submit({required String email, String? username}) async {
    state = const SubmissionInProgress();
    try {
      await runGuarded(
        ref,
        () => ref
            .read(authRepositoryProvider)
            .submitAccountRequest(email: email, username: username),
      );
      state = const SubmissionSuccess();
    } catch (error) {
      state = SubmissionFailure(userFacingErrorMessage(error));
    }
  }
}

final accountRequestControllerProvider =
    NotifierProvider<AccountRequestController, SubmissionState>(
      AccountRequestController.new,
    );
