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

  /// The account has used up its traffic allowance.
  ///
  /// A status code rather than the message, because the wording belongs
  /// to the server and matching on it would break the first time somebody
  /// rephrased it. Nothing else in this API answers 402.
  bool get isQuotaExhausted => statusCode == 402;

  /// The server takes no new connections while under maintenance. Nothing
  /// else in this API answers 423.
  bool get isServerMaintenance => statusCode == 423;

  /// Sign-in refused: the account is at its device limit. The server sends
  /// a code rather than a sentence, so the app can say it in any language.
  bool get isDeviceLimitReached =>
      statusCode == 403 && detail == 'device_limit_reached';

  /// Sign-in refused: the account's expiry date has passed.
  bool get isAccountExpired => statusCode == 403 && detail == 'account_expired';

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
