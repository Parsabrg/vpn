import 'dart:async';
import 'dart:io';
import 'dart:math';

import 'package:flutter/foundation.dart';

import 'local_proxy.dart' show dnsQuery;

/// Where Xray may look up Cloudflare's ECH keys, most preferred first.
///
/// Every route through Cloudflare depends on this one lookup: with no key
/// there is no ECH, and without ECH the route's name is visible and
/// throttled (measured from Iran, 2026-10-15). One blocked resolver must not
/// take every route down, so the app checks which of these answers before
/// connecting. Plain UDP to all three answered on that line while 1.1.1.1
/// over HTTPS was reset.
const List<String> echLookupServers = <String>[
  'udp://1.1.1.1',
  'udp://8.8.8.8',
  'udp://9.9.9.9',
];

/// Used without checking when none of [echLookupServers] answers: Google's
/// DNS over HTTPS by address, which needs no name in the handshake (the
/// name `dns.google` is reset there) and worked on the same line.
const String echLastResortServer = 'https://8.8.8.8/dns-query';

String? _chosen;
DateTime _chosenAt = DateTime.fromMillisecondsSinceEpoch(0);

/// [echConfigList] with its lookup server replaced by the one that answered
/// at the last check. Left alone when nothing has been checked yet, when it
/// is a key list rather than a lookup, or when its server is not one of
/// ours -- a link's own choice of resolver is kept.
String withWorkingEchServer(String echConfigList) {
  final String? chosen = _chosen;
  final int plus = echConfigList.indexOf('+');
  if (chosen == null || plus < 0) {
    return echConfigList;
  }
  if (!echLookupServers.contains(echConfigList.substring(plus + 1))) {
    return echConfigList;
  }
  return '${echConfigList.substring(0, plus)}+$chosen';
}

/// Checks which lookup server answers for the name in [echConfigList], at
/// most every ten minutes, so [withWorkingEchServer] can use it.
///
/// The servers are asked at once and the first in order of preference that
/// answers wins, so a working 1.1.1.1 costs one round trip and a dead one at
/// most [timeout].
Future<void> refreshEchServer(
  String? echConfigList, {
  Duration timeout = const Duration(seconds: 2),
  @visibleForTesting Future<bool> Function(String server, String name)? ask,
}) async {
  final int plus = echConfigList?.indexOf('+') ?? -1;
  if (echConfigList == null || plus < 1 || !echConfigList.contains('://')) {
    return;
  }
  if (_chosen != null &&
      DateTime.now().difference(_chosenAt) < const Duration(minutes: 10)) {
    return;
  }
  final String name = echConfigList.substring(0, plus);
  final Future<bool> Function(String, String) query = ask ?? _answers;
  final List<Future<bool>> attempts = <Future<bool>>[
    for (final String server in echLookupServers)
      query(server, name)
          .timeout(timeout, onTimeout: () => false)
          .catchError((Object _) => false),
  ];
  String chosen = echLastResortServer;
  for (int i = 0; i < attempts.length; i++) {
    if (await attempts[i]) {
      chosen = echLookupServers[i];
      break;
    }
  }
  _chosen = chosen;
  _chosenAt = DateTime.now();
}

@visibleForTesting
void resetEchServer() {
  _chosen = null;
  _chosenAt = DateTime.fromMillisecondsSinceEpoch(0);
}

/// Whether [server] (`udp://address`) answers [name]'s HTTPS record, the one
/// that carries the ECH keys.
Future<bool> _answers(String server, String name) async {
  final InternetAddress address = InternetAddress(
    server.substring('udp://'.length),
  );
  final RawDatagramSocket socket = await RawDatagramSocket.bind(
    InternetAddress.anyIPv4,
    0,
  );
  try {
    final int id = Random().nextInt(0x10000);
    socket.send(dnsQuery(id, name, type: 65), address, 53);
    await for (final RawSocketEvent event in socket) {
      if (event != RawSocketEvent.read) {
        continue;
      }
      final Datagram? datagram = socket.receive();
      if (datagram != null && datagram.address == address) {
        return dnsAnswerHasType(datagram.data, id, 65);
      }
    }
    return false;
  } finally {
    socket.close();
  }
}

/// Whether [answer] answers question [id] without error and holds a record
/// of [type].
@visibleForTesting
bool dnsAnswerHasType(Uint8List answer, int id, int type) {
  if (answer.length < 12 ||
      (answer[0] << 8 | answer[1]) != id ||
      answer[2] & 0x80 == 0 ||
      answer[3] & 0x0f != 0) {
    return false;
  }
  int at = 12;
  void skipName() {
    while (true) {
      final int length = answer[at];
      if (length & 0xc0 == 0xc0) {
        at += 2;
        return;
      }
      at += 1 + length;
      if (length == 0) {
        return;
      }
    }
  }

  try {
    for (int q = answer[4] << 8 | answer[5]; q > 0; q--) {
      skipName();
      at += 4;
    }
    for (int a = answer[6] << 8 | answer[7]; a > 0; a--) {
      skipName();
      final int end = at + 10 + (answer[at + 8] << 8 | answer[at + 9]);
      if (end > answer.length) {
        return false;
      }
      if ((answer[at] << 8 | answer[at + 1]) == type) {
        return true;
      }
      at = end;
    }
    return false;
  } on RangeError {
    return false;
  }
}
