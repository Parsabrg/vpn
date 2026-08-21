import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../network/api_client.dart';
import '../network/api_exception.dart';
import 'token_pair.dart';
import 'user_principal.dart';

/// Matches the API's `platform` enum exactly (`"android" | "windows"`, no
/// `"ios"` -- see `services/api/src/nebula_api/models/types.py`).
enum DevicePlatform { android, windows }

extension DevicePlatformWireValue on DevicePlatform {
  String get wireValue => name;
}

abstract interface class AuthRepository {
  Future<TokenPair> login({
    required String identifier,
    required String password,
    required String? deviceId,
    required String deviceName,
    required DevicePlatform platform,
    required String clientVersion,
  });

  Future<TokenPair> refresh(String refreshToken);

  Future<void> logout(String refreshToken);

  Future<UserPrincipal> me(String accessToken);

  Future<void> requestPasswordReset(String identifier);

  Future<void> confirmPasswordReset({
    required String token,
    required String newPassword,
  });

  Future<void> submitAccountRequest({required String email, String? username});

  Future<void> activateAccount({
    required String token,
    required String newPassword,
  });
}

class DioAuthRepository implements AuthRepository {
  DioAuthRepository(this._dio);

  final Dio _dio;

  @override
  Future<TokenPair> login({
    required String identifier,
    required String password,
    required String? deviceId,
    required String deviceName,
    required DevicePlatform platform,
    required String clientVersion,
  }) async {
    final Response<dynamic> response =
        await _post('/v1/auth/login', <String, dynamic>{
          'identifier': identifier,
          'password': password,
          'device_id': deviceId,
          'device_name': deviceName,
          'platform': platform.wireValue,
          'client_version': clientVersion,
        });
    return _tokenPairFrom(response.data as Map<String, dynamic>);
  }

  @override
  Future<TokenPair> refresh(String refreshToken) async {
    final Response<dynamic> response = await _post(
      '/v1/auth/refresh',
      <String, dynamic>{'refresh_token': refreshToken},
    );
    return _tokenPairFrom(response.data as Map<String, dynamic>);
  }

  @override
  Future<void> logout(String refreshToken) async {
    await _post('/v1/auth/logout', <String, dynamic>{
      'refresh_token': refreshToken,
    });
  }

  @override
  Future<UserPrincipal> me(String accessToken) async {
    try {
      final Response<dynamic> response = await _dio.get<dynamic>(
        '/v1/auth/me',
        options: Options(
          headers: <String, String>{'Authorization': 'Bearer $accessToken'},
        ),
      );
      final Map<String, dynamic> data = response.data as Map<String, dynamic>;
      return UserPrincipal(
        userId: data['user_id'] as String,
        sessionId: data['session_id'] as String,
        deviceId: data['device_id'] as String,
      );
    } on DioException catch (error) {
      throw translateDioException(error);
    }
  }

  @override
  Future<void> requestPasswordReset(String identifier) async {
    await _post('/v1/auth/password-reset/request', <String, dynamic>{
      'identifier': identifier,
    });
  }

  @override
  Future<void> confirmPasswordReset({
    required String token,
    required String newPassword,
  }) async {
    await _post('/v1/auth/password-reset/confirm', <String, dynamic>{
      'token': token,
      'new_password': newPassword,
    });
  }

  @override
  Future<void> submitAccountRequest({
    required String email,
    String? username,
  }) async {
    await _post('/v1/account-requests/', <String, dynamic>{
      'email': email,
      'username': ?username,
    });
  }

  @override
  Future<void> activateAccount({
    required String token,
    required String newPassword,
  }) async {
    await _post('/v1/account-requests/activate', <String, dynamic>{
      'token': token,
      'new_password': newPassword,
    });
  }

  Future<Response<dynamic>> _post(
    String path,
    Map<String, dynamic> body,
  ) async {
    try {
      return await _dio.post<dynamic>(path, data: body);
    } on DioException catch (error) {
      throw translateDioException(error);
    }
  }

  TokenPair _tokenPairFrom(Map<String, dynamic> data) {
    return TokenPair(
      accessToken: data['access_token'] as String,
      refreshToken: data['refresh_token'] as String,
      expiresIn: Duration(seconds: data['expires_in'] as int),
    );
  }
}

final authRepositoryProvider = Provider<AuthRepository>((Ref ref) {
  return DioAuthRepository(ref.watch(dioProvider));
});
