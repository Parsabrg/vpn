import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../network/api_client.dart';
import '../network/api_exception.dart';

/// The caller's own account, as `GET /v1/account` returns it.
class AccountSummary {
  const AccountSummary({
    required this.email,
    required this.state,
    required this.deviceLimit,
    required this.devicesInUse,
    required this.usedBytes,
    int? lifetimeBytes,
    this.username,
    this.expiresAt,
    this.quotaBytes,
    this.remainingBytes,
  }) : lifetimeBytes = lifetimeBytes ?? usedBytes;

  final String email;
  final String? username;
  final String state;
  final int deviceLimit;
  final int devicesInUse;

  /// Traffic transferred on the current allowance, both directions, across
  /// every credential this account's devices hold. Starts again from zero
  /// when an allowance is granted, because "left" is measured against it.
  final int usedBytes;

  /// Everything this account has ever transferred, on every device it has
  /// had. Never starts again. A server too old to report it gets [usedBytes],
  /// which is the same figure until an allowance has been granted.
  final int lifetimeBytes;

  /// Null means unmetered -- not "a very large allowance". The two render
  /// differently and must not be collapsed.
  final int? quotaBytes;

  /// Null when unmetered. Never negative: an over-quota account has nothing
  /// left rather than a negative allowance.
  final int? remainingBytes;

  /// Whether this account has a traffic allowance at all.
  bool get isMetered => quotaBytes != null;

  /// How much of the allowance is spent, 0..1. Null when unmetered, so a bar
  /// can be omitted rather than drawn full or empty and misread.
  double? get usedFraction {
    final int? quota = quotaBytes;
    if (quota == null || quota <= 0) {
      return null;
    }
    return (usedBytes / quota).clamp(0, 1).toDouble();
  }

  /// Null means no expiry is set, which is not the same as expired. The two
  /// must render differently, so this stays nullable rather than defaulting
  /// to some far-future date.
  final DateTime? expiresAt;

  /// Whether an expiry exists and has passed.
  ///
  /// Asked here rather than at each call site so "no expiry" cannot be
  /// mistaken for "expired" by a comparison against a null-coalesced value.
  bool hasExpiredAt(DateTime now) {
    final DateTime? expiry = expiresAt;
    return expiry != null && !expiry.isAfter(now);
  }
}

/// One device on the account, as `GET /v1/account/devices` returns it.
class AccountDevice {
  const AccountDevice({
    required this.id,
    required this.name,
    required this.platform,
    required this.state,
    required this.clientVersion,
    required this.registeredAt,
    required this.isCurrent,
    required this.serverCodes,
  });

  final String id;
  final String name;

  /// `android` or `windows`.
  final String platform;
  final String state;
  final String clientVersion;
  final DateTime registeredAt;

  /// True for the device making the request. It is the one device that
  /// cannot be revoked -- doing so would drop this device's own tunnel.
  final bool isCurrent;

  /// Servers this device holds a live credential on. Empty means registered
  /// and provisioned nothing, which is a state worth showing rather than
  /// hiding.
  final List<String> serverCodes;
}

abstract interface class AccountRepository {
  Future<AccountSummary> fetchAccount();
  Future<List<AccountDevice>> listDevices();
  Future<void> revokeDevice(String deviceId);

  /// Changes the password; the server signs out every other device.
  Future<void> changePassword({
    required String currentPassword,
    required String newPassword,
  });

  /// Deletes the account for good. The password is asked for again.
  Future<void> deleteAccount(String password);
}

class DioAccountRepository implements AccountRepository {
  DioAccountRepository(this._dio);

  final Dio _dio;

  @override
  Future<AccountSummary> fetchAccount() async {
    try {
      final Response<dynamic> response = await _dio.get<dynamic>('/v1/account');
      final Map<String, dynamic> data = response.data as Map<String, dynamic>;
      return AccountSummary(
        email: data['email'] as String,
        username: data['username'] as String?,
        state: data['state'] as String,
        deviceLimit: data['device_limit'] as int,
        devicesInUse: data['devices_in_use'] as int,
        expiresAt: _parseTime(data['expires_at']),
        usedBytes: (data['used_bytes'] as num?)?.toInt() ?? 0,
        lifetimeBytes: (data['lifetime_bytes'] as num?)?.toInt(),
        quotaBytes: (data['quota_bytes'] as num?)?.toInt(),
        remainingBytes: (data['remaining_bytes'] as num?)?.toInt(),
      );
    } on DioException catch (error) {
      throw translateDioException(error);
    }
  }

  @override
  Future<List<AccountDevice>> listDevices() async {
    try {
      final Response<dynamic> response = await _dio.get<dynamic>(
        '/v1/account/devices',
      );
      final Map<String, dynamic> data = response.data as Map<String, dynamic>;
      final List<dynamic> items = data['items'] as List<dynamic>;
      return items.map((dynamic rawItem) {
        final Map<String, dynamic> item = rawItem as Map<String, dynamic>;
        final List<dynamic> codes = item['server_codes'] as List<dynamic>;
        return AccountDevice(
          id: item['id'] as String,
          name: item['name'] as String,
          platform: item['platform'] as String,
          state: item['state'] as String,
          clientVersion: item['client_version'] as String,
          registeredAt: DateTime.parse(item['registered_at'] as String),
          isCurrent: item['is_current'] as bool,
          serverCodes: codes.cast<String>(),
        );
      }).toList();
    } on DioException catch (error) {
      throw translateDioException(error);
    }
  }

  @override
  Future<void> revokeDevice(String deviceId) async {
    try {
      await _dio.post<dynamic>('/v1/account/devices/$deviceId/revoke');
    } on DioException catch (error) {
      throw translateDioException(error);
    }
  }

  @override
  Future<void> changePassword({
    required String currentPassword,
    required String newPassword,
  }) async {
    try {
      await _dio.post<dynamic>(
        '/v1/account/password',
        data: <String, String>{
          'current_password': currentPassword,
          'new_password': newPassword,
        },
      );
    } on DioException catch (error) {
      throw translateDioException(error);
    }
  }

  @override
  Future<void> deleteAccount(String password) async {
    try {
      await _dio.post<dynamic>(
        '/v1/account/delete',
        data: <String, String>{'password': password},
      );
    } on DioException catch (error) {
      throw translateDioException(error);
    }
  }

  /// Parses a nullable timestamp without inventing one.
  ///
  /// A malformed value is treated as absent rather than thrown on: the
  /// account screen is not worth failing over a date it can simply not show,
  /// and the fields around it are still useful.
  static DateTime? _parseTime(Object? raw) {
    if (raw is! String) {
      return null;
    }
    return DateTime.tryParse(raw);
  }
}

final accountRepositoryProvider = Provider<AccountRepository>((Ref ref) {
  return DioAccountRepository(ref.watch(dioProvider));
});
