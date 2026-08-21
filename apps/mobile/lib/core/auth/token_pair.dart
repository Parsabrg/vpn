/// The access/refresh token pair returned by `/v1/auth/login` and
/// `/v1/auth/refresh` (identical response shape for both).
class TokenPair {
  const TokenPair({
    required this.accessToken,
    required this.refreshToken,
    required this.expiresIn,
  });

  final String accessToken;
  final String refreshToken;

  /// Access-token lifetime, from the API's `expires_in` (seconds).
  final Duration expiresIn;
}
