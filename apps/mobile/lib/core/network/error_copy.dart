import 'api_exception.dart';

/// Renders any caught error into copy safe to show a user, without ever
/// inventing detail the API didn't actually provide.
String userFacingErrorMessage(Object error) {
  if (error is NebulaConnectivityException) {
    return "You're offline. Check your connection and try again.";
  }
  if (error is NebulaApiException) {
    if (error.isRateLimited) {
      return 'Too many attempts. Please wait and try again.';
    }
    return error.detail;
  }
  return 'Something went wrong. Please try again.';
}
