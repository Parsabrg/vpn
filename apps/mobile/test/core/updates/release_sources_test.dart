import 'dart:convert';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/updates/update_check.dart';

class _Answering implements HttpClientAdapter {
  _Answering(this.body);

  final Object? body;
  String? path;

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<Uint8List>? requestStream,
    Future<void>? cancelFuture,
  ) async {
    path = options.path;
    if (body == null) {
      throw DioException(
        requestOptions: options,
        type: DioExceptionType.badResponse,
      );
    }
    return ResponseBody.fromString(
      jsonEncode(body),
      200,
      headers: <String, List<String>>{
        Headers.contentTypeHeader: <String>['application/json'],
      },
    );
  }

  @override
  void close({bool force = false}) {}
}

class _Fixed implements ReleaseSource {
  _Fixed(this.release);

  final Map<String, dynamic>? release;
  int asked = 0;

  @override
  Future<Map<String, dynamic>?> latest() async {
    asked++;
    return release;
  }
}

NebulaReleaseSource _api(_Answering network) => NebulaReleaseSource(
  Dio(BaseOptions(baseUrl: 'https://api.test'))..httpClientAdapter = network,
);

void main() {
  test(
    'the API\'s version becomes an update on the GitHub release page',
    () async {
      final _Answering network = _Answering(<String, Object?>{
        'version': '0.1.25',
      });
      final Map<String, dynamic>? release = await _api(network).latest();

      expect(network.path, '/v1/client/release');
      final AvailableUpdate? update = updateFromRelease(release!, '0.1.20');
      expect(update!.version, '0.1.25');
      expect(
        update.page.toString(),
        'https://github.com/$releasesRepository/releases/tag/v0.1.25',
      );
      expect(updateFromRelease(release, '0.1.25'), isNull);
    },
  );

  test('no version, a strange one, or no answer offers nothing', () async {
    expect(
      await _api(_Answering(<String, Object?>{'version': null})).latest(),
      isNull,
    );
    expect(
      await _api(_Answering(<String, Object?>{'version': '../x'})).latest(),
      isNull,
    );
    expect(await _api(_Answering(null)).latest(), isNull);
  });

  test(
    'GitHub is asked first, and the API only when it knows nothing',
    () async {
      final _Fixed github = _Fixed(<String, dynamic>{'tag_name': 'v0.1.26'});
      final _Fixed api = _Fixed(<String, dynamic>{'tag_name': 'v0.1.25'});
      expect(
        (await FirstReleaseSource(<ReleaseSource>[
          github,
          api,
        ]).latest())!['tag_name'],
        'v0.1.26',
      );
      expect(api.asked, 0);

      final _Fixed privateRepo = _Fixed(null);
      expect(
        (await FirstReleaseSource(<ReleaseSource>[
          privateRepo,
          api,
        ]).latest())!['tag_name'],
        'v0.1.25',
      );
      expect(
        await FirstReleaseSource(<ReleaseSource>[privateRepo]).latest(),
        isNull,
      );
    },
  );
}
