import 'dart:io';

import 'package:dio/dio.dart';
import 'package:dio/io.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../pairing/pairing.dart';
import '../pairing/pairing_providers.dart';
import '../storage/storage_providers.dart';
import 'api_config.dart';
import 'auth_interceptor.dart';
import 'route_fallback.dart';

/// Where an unpaired app's requests go: nowhere. Nothing is sent before
/// pairing, and a request that is sent by mistake fails to resolve rather
/// than reaching someone's server.
const String unpairedBaseUrl = 'https://unpaired.invalid';

/// The single shared [Dio] instance. [AuthInterceptor] handles attaching
/// bearer tokens and retrying once after a token refresh -- callers never
/// need to think about authentication headers themselves.
///
/// Built once and pointed at a new deployment in place when the app is
/// paired again, rather than rebuilt: everything holding it would otherwise
/// be rebuilt with it, mid-flow.
final dioProvider = Provider<Dio>((Ref ref) {
  final Pairing? pairing = ref.read(pairingProvider);
  final Dio dio = Dio(
    BaseOptions(
      baseUrl: pairing?.apiUrl ?? unpairedBaseUrl,
      connectTimeout: ApiConfig.connectTimeout,
      receiveTimeout: ApiConfig.receiveTimeout,
      contentType: 'application/json',
    ),
  );
  final RouteFallbackInterceptor routes = RouteFallbackInterceptor(
    dio: dio,
    routes: routesFor(pairing),
    preferences: () => ref.read(sharedPreferencesProvider),
  );
  dio.httpClientAdapter = adapterFor(pairing);
  dio.interceptors.add(routes);
  dio.interceptors.add(AuthInterceptor(ref));
  ref.listen<Pairing?>(pairingProvider, (Pairing? previous, Pairing? next) {
    dio.httpClientAdapter = adapterFor(next);
    routes.retarget(routesFor(next));
  });
  return dio;
});

/// The hosts of every address the API is known by, for the tunnel to carry
/// them however it routes everything else.
final apiHostsProvider = Provider<List<String>>((Ref ref) {
  try {
    return <String>{
      for (final String url
          in ref
              .read(dioProvider)
              .interceptors
              .whereType<RouteFallbackInterceptor>()
              .first
              .known)
        if (Uri.tryParse(url)?.host case final String host when host.isNotEmpty)
          host,
    }.toList();
  } on Object {
    // No API client (a test, or not paired yet): nothing to carry.
    return const <String>[];
  }
});

/// Moves the API to its next known address; see
/// [RouteFallbackInterceptor.moveOn].
final moveApiRouteProvider = Provider<bool Function()>(
  (Ref ref) =>
      () => ref
          .read(dioProvider)
          .interceptors
          .whereType<RouteFallbackInterceptor>()
          .first
          .moveOn(),
);

/// The paired address first. The build's backup addresses only belong to the
/// build's own deployment, so it is used only while that is the one paired.
List<String> routesFor(Pairing? pairing) {
  if (pairing == null) {
    return <String>[unpairedBaseUrl];
  }
  final bool isBuildPreset =
      pairing.deploymentId == null && pairing.apiUrl == ApiConfig.presetBaseUrl;
  return <String>[
    pairing.apiUrl,
    if (isBuildPreset) ...ApiConfig.backupBaseUrls,
  ];
}

/// Trusts the deployment's own CA when it has one, alongside the platform's
/// roots: the paired address is verified against the pinned CA, and the
/// extra addresses the API names later (a CDN in front of it, typically)
/// carry publicly trusted certificates.
HttpClientAdapter adapterFor(Pairing? pairing) {
  final String? ca = pairing?.caCertificatePem;
  return IOHttpClientAdapter(
    createHttpClient: ca == null
        ? null
        : () => HttpClient(context: pinnedContext(ca, alsoSystem: true)),
  );
}
