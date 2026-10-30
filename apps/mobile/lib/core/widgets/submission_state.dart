/// Generic form-submission state shared by every screen that posts to a
/// single endpoint and shows a result (account request, activation,
/// password reset). A closed sum type so screens can exhaustively `switch`
/// rather than juggling separate `isLoading`/`error` flags.
sealed class SubmissionState {
  const SubmissionState();
}

class SubmissionIdle extends SubmissionState {
  const SubmissionIdle();
}

class SubmissionInProgress extends SubmissionState {
  const SubmissionInProgress();
}

/// Reached only on the API's uniform 202/204 success -- carries no data, so
/// there is exactly one success UI regardless of what was submitted. This
/// is what enforces this app's side of the API's neutral-response design:
/// there is no code path that could render a different success message for
/// "account exists" vs. "account doesn't exist," because the client never
/// receives that distinction in the first place.
class SubmissionSuccess extends SubmissionState {
  const SubmissionSuccess();
}

class SubmissionFailure extends SubmissionState {
  const SubmissionFailure(this.message);

  final String message;
}
