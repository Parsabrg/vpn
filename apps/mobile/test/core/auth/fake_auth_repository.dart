import 'package:nebula_mobile/core/auth/auth_repository.dart';
import 'package:nebula_mobile/core/auth/token_pair.dart';
import 'package:nebula_mobile/core/auth/user_principal.dart';

/// Hand-written fake -- no mocking package needed for this small interface.
class FakeAuthRepository implements AuthRepository {
  int loginCalls = 0;
  int refreshCalls = 0;
  int logoutCalls = 0;
  int meCalls = 0;
  int submitAccountRequestCalls = 0;

  TokenPair Function()? loginResult;
  Object? loginError;

  TokenPair Function()? refreshResult;
  Object? refreshError;

  UserPrincipal Function()? meResult;
  Object? meError;

  @override
  Future<TokenPair> login({
    required String identifier,
    required String password,
    required String? deviceId,
    required String deviceName,
    required DevicePlatform platform,
    required String clientVersion,
  }) async {
    loginCalls++;
    final Object? error = loginError;
    if (error != null) {
      throw error;
    }
    return loginResult!();
  }

  @override
  Future<TokenPair> refresh(String refreshToken) async {
    refreshCalls++;
    final Object? error = refreshError;
    if (error != null) {
      throw error;
    }
    return refreshResult!();
  }

  @override
  Future<void> logout(String refreshToken) async {
    logoutCalls++;
  }

  @override
  Future<UserPrincipal> me(String accessToken) async {
    meCalls++;
    final Object? error = meError;
    if (error != null) {
      throw error;
    }
    return meResult!();
  }

  @override
  Future<void> requestPasswordReset(String identifier) async {}

  @override
  Future<void> confirmPasswordReset({
    required String token,
    required String newPassword,
  }) async {}

  @override
  Future<void> submitAccountRequest({
    required String email,
    String? username,
  }) async {
    submitAccountRequestCalls++;
  }

  @override
  Future<void> activateAccount({
    required String token,
    required String newPassword,
  }) async {}
}
