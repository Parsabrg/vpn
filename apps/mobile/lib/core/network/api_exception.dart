import 'package:dio/dio.dart';

/// A parsed API error response.
///
/// Non-validation errors are `{"detail": "<generic string>"}`; validation
/// (422) errors are `{"detail": [{"type","loc","msg"}, ...]}`. Both collapse
/// to a single human-readable [detail] string here. Per this API's
/// neutral-response design, [detail] is deliberately generic for most
/// failure modes (e.g. login) -- UI code must not try to infer more from it
/// than the server intended to reveal.
class NebulaApiException implements Exception {
  const NebulaApiException({
    required this.statusCode,
    required this.detail,
    this.retryAfter,
  });

  final int? statusCode;
  final String detail;
  final Duration? retryAfter;

  bool get isRateLimited => statusCode == 429;
  bool get isUnauthorized => statusCode == 401;
  bool get isConflict => statusCode == 409;

  @override
  String toString() => 'NebulaApiException($statusCode): $detail';
}

/// Thrown when a request could not reach the API at all (offline, DNS
/// failure, timeout) -- distinct from a server-returned error, since the UI
/// treats "offline" and "the server said no" differently.
class NebulaConnectivityException implements Exception {
  const NebulaConnectivityException(this.message);

  final String message;

  @override
  String toString() => 'NebulaConnectivityException($message)';
}

const Set<DioExceptionType> _connectivityErrorTypes = <DioExceptionType>{
  DioExceptionType.connectionError,
  DioExceptionType.connectionTimeout,
  DioExceptionType.receiveTimeout,
  DioExceptionType.sendTimeout,
};

/// Translates a raw [DioException] into either a [NebulaConnectivityException]
/// (no response reached us) or a [NebulaApiException] (the server responded
/// with an error).
Object translateDioException(DioException error) {
  final Response<dynamic>? response = error.response;
  if (response == null || _connectivityErrorTypes.contains(error.type)) {
    return NebulaConnectivityException(
      error.message ?? 'Could not reach the server',
    );
  }

  String detail = 'Request was not accepted';
  final dynamic data = response.data;
  if (data is Map<String, dynamic>) {
    final dynamic rawDetail = data['detail'];
    if (rawDetail is String && rawDetail.isNotEmpty) {
      detail = rawDetail;
    } else if (rawDetail is List<dynamic>) {
      final String joined = rawDetail
          .whereType<Map<String, dynamic>>()
          .map((Map<String, dynamic> item) => item['msg'])
          .whereType<String>()
          .join('; ');
      if (joined.isNotEmpty) {
        detail = joined;
      }
    }
  }

  Duration? retryAfter;
  final String? retryAfterHeader = response.headers.value('retry-after');
  if (retryAfterHeader != null) {
    final int? seconds = int.tryParse(retryAfterHeader);
    if (seconds != null) {
      retryAfter = Duration(seconds: seconds);
    }
  }

  return NebulaApiException(
    statusCode: response.statusCode,
    detail: detail,
    retryAfter: retryAfter,
  );
}
