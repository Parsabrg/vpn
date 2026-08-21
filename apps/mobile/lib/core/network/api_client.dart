import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'api_config.dart';
import 'auth_interceptor.dart';

/// The single shared [Dio] instance. [AuthInterceptor] handles attaching
/// bearer tokens and retrying once after a token refresh -- callers never
/// need to think about authentication headers themselves.
final dioProvider = Provider<Dio>((Ref ref) {
  final Dio dio = Dio(
    BaseOptions(
      baseUrl: ApiConfig.baseUrl,
      connectTimeout: ApiConfig.connectTimeout,
      receiveTimeout: ApiConfig.receiveTimeout,
      contentType: 'application/json',
    ),
  );
  dio.interceptors.add(AuthInterceptor(ref));
  return dio;
});
