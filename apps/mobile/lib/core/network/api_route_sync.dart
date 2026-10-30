import 'dart:convert';

import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../storage/storage_providers.dart';
import 'api_client.dart';
import 'route_fallback.dart';

/// Asks the server, while it can be reached, which addresses it can be
/// reached at -- and keeps the answer for when it cannot.
///
/// This is the part that makes a block answerable without a release. An
/// address added to the server after a build shipped is otherwise invisible
/// to every phone already carrying that build: the position every 0.1.10
/// install is in today, waiting for an APK because the address it knows is
/// the one that was blocked.
///
/// Every failure is ignored on purpose. This is housekeeping done in the
/// background of a screen the person asked for, and a stale list is exactly
/// as useful as it was a minute ago.
class ApiRouteSync {
  ApiRouteSync(this._dio, this._preferences);

  final Dio _dio;
  final SharedPreferences _preferences;

  Future<void> refresh() async {
    try {
      final Response<dynamic> response = await _dio.get<dynamic>('/v1/routes/');
      final Object? body = response.data;
      if (body is! Map<String, dynamic>) {
        return;
      }
      final Object? routes = body['routes'];
      if (routes is! List<Object?>) {
        return;
      }
      final List<String> https = routes
          .whereType<String>()
          .where((String route) => route.startsWith('https://'))
          .toList();
      // An empty list is a real answer -- this deployment has no extra
      // addresses -- and replacing the stored one with it is correct: an
      // address the server has dropped should stop being tried.
      await _preferences.setString(kLearnedRoutesKey, jsonEncode(https));
    } catch (_) {
      // See above: never worth failing anything the person asked for.
    }
  }
}

final apiRouteSyncProvider = Provider<ApiRouteSync>((Ref ref) {
  return ApiRouteSync(
    ref.watch(dioProvider),
    ref.watch(sharedPreferencesProvider),
  );
});
