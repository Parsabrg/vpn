import 'package:nebula_mobile/core/account/account_repository.dart';

class FakeAccountRepository implements AccountRepository {
  AccountSummary? account;
  List<AccountDevice> devices = <AccountDevice>[];
  Object? accountError;
  Object? devicesError;
  Object? revokeError;

  final List<String> revoked = <String>[];
  int fetchAccountCalls = 0;

  @override
  Future<AccountSummary> fetchAccount() async {
    fetchAccountCalls++;
    final Object? error = accountError;
    if (error != null) {
      throw error;
    }
    return account!;
  }

  @override
  Future<List<AccountDevice>> listDevices() async {
    final Object? error = devicesError;
    if (error != null) {
      throw error;
    }
    return devices;
  }

  @override
  Future<void> revokeDevice(String deviceId) async {
    final Object? error = revokeError;
    if (error != null) {
      throw error;
    }
    revoked.add(deviceId);
    // Mirrors the server: the row goes, and the count follows it. A fake that
    // dropped the row but left the count would hide exactly the drift these
    // screens are meant to avoid.
    devices = devices
        .where((AccountDevice device) => device.id != deviceId)
        .toList();
    final AccountSummary? current = account;
    if (current != null) {
      account = AccountSummary(
        email: current.email,
        username: current.username,
        state: current.state,
        deviceLimit: current.deviceLimit,
        devicesInUse: devices.length,
        expiresAt: current.expiresAt,
        usedBytes: current.usedBytes,
        lifetimeBytes: current.lifetimeBytes,
        quotaBytes: current.quotaBytes,
        remainingBytes: current.remainingBytes,
      );
    }
  }

  /// What was asked of the password change and deletion, in order.
  final List<String> securityCalls = <String>[];
  Object? securityError;

  @override
  Future<void> changePassword({
    required String currentPassword,
    required String newPassword,
  }) async {
    securityCalls.add('change:$currentPassword>$newPassword');
    final Object? error = securityError;
    if (error != null) {
      throw error;
    }
  }

  @override
  Future<void> deleteAccount(String password) async {
    securityCalls.add('delete:$password');
    final Object? error = securityError;
    if (error != null) {
      throw error;
    }
  }
}
