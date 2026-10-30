import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// The tunnel's local SOCKS5 proxy on 127.0.0.1: its port and credentials.
///
/// The proxy is how traffic gets from the VPN interface into the engine:
/// tun2socks reads packets off the interface and dials it.
///
/// Credentials, because loopback is shared by every app on the phone. With
/// none, any of them could use the proxy too -- including an app excluded from
/// the tunnel by split tunnelling, which in practice is usually a domestic
/// app, and which would learn the server's address from the first answer.
/// Confirmed on a phone before they existed: `curl --socks5-hostname
/// 127.0.0.1:10808 https://api.ipify.org` from the adb shell printed the
/// server's IP.
///
/// A port of its own, because 10808 -- the one this used to be fixed to -- is
/// v2rayNG's default too. With v2rayNG running as a proxy, the engine here
/// could not take the port and the connection failed.
class LocalProxy {
  const LocalProxy({
    required this.port,
    required this.username,
    required this.password,
  });

  /// A free loopback port, a 64-bit username and a 128-bit password from the
  /// platform's secure random source. Hex, so no character means anything in
  /// JSON, YAML or a command line.
  ///
  /// The port is found by asking the system for one and releasing it again.
  /// Something could take it in the moment before the engine does; that is a
  /// failed connect, reported as one, not a silent fault.
  static Future<LocalProxy> generate([Random? random]) async {
    final ServerSocket probe = await ServerSocket.bind(
      InternetAddress.loopbackIPv4,
      0,
    );
    final int port = probe.port;
    await probe.close();
    final Random source = random ?? Random.secure();
    String hex(int bytes) => List<String>.generate(
      bytes,
      (_) => source.nextInt(256).toRadixString(16).padLeft(2, '0'),
    ).join();
    return LocalProxy(port: port, username: 'n${hex(8)}', password: hex(16));
  }

  final int port;
  final String username;
  final String password;

  LocalProxy withPort(int port) =>
      LocalProxy(port: port, username: username, password: password);
}

/// The username and password of the proxy in local proxy mode.
///
/// Kept, unlike the VPN mode's, because apps are set up with them by hand:
/// new ones on every connection would mean re-entering them in every app
/// every time. Generated once, in secure storage beside the session.
abstract interface class LocalProxyAccountStore {
  Future<LocalProxy> readOrCreate(int port);
}

class SecureLocalProxyAccountStore implements LocalProxyAccountStore {
  SecureLocalProxyAccountStore({FlutterSecureStorage? storage})
    : _storage = storage ?? const FlutterSecureStorage();

  static const String _usernameKey = 'nebula.local_proxy_username';
  static const String _passwordKey = 'nebula.local_proxy_password';

  final FlutterSecureStorage _storage;

  @override
  Future<LocalProxy> readOrCreate(int port) async {
    final String? username = await _storage.read(key: _usernameKey);
    final String? password = await _storage.read(key: _passwordKey);
    if (username != null && password != null) {
      return LocalProxy(port: port, username: username, password: password);
    }
    final LocalProxy created = (await LocalProxy.generate()).withPort(port);
    await _storage.write(key: _usernameKey, value: created.username);
    await _storage.write(key: _passwordKey, value: created.password);
    return created;
  }
}

/// In-memory fake for tests.
class InMemoryLocalProxyAccountStore implements LocalProxyAccountStore {
  String username = 'n8899aabbccddeeff';
  String password = '00112233445566778899aabbccddeeff';

  @override
  Future<LocalProxy> readOrCreate(int port) async {
    return LocalProxy(port: port, username: username, password: password);
  }
}

final localProxyAccountStoreProvider = Provider<LocalProxyAccountStore>(
  (Ref ref) => SecureLocalProxyAccountStore(),
);

/// Whether something accepts connections on a loopback port.
///
/// How local proxy mode tells a proxy is up, having no VPN network for
/// Android to report -- and how it tells, before starting, that another app
/// already holds the chosen port.
Future<bool> isLoopbackPortOpen(int port) async {
  try {
    final Socket socket = await Socket.connect(
      InternetAddress.loopbackIPv4,
      port,
      timeout: const Duration(seconds: 1),
    );
    socket.destroy();
    return true;
  } on Object {
    return false;
  }
}

final loopbackPortProbeProvider = Provider<Future<bool> Function(int)>(
  (Ref ref) => isLoopbackPortOpen,
);

/// Where a connection's local proxy comes from. A provider so tests can hand
/// out a fixed one instead of binding sockets.
final localProxyFactoryProvider = Provider<Future<LocalProxy> Function()>(
  (Ref ref) => LocalProxy.generate,
);

/// Whether an HTTPS request gets an answer through [proxy] -- through the
/// engine and its server, that is.
///
/// On Android this app is kept out of its own tunnel (the engine's sockets
/// must not loop back into it), so an ordinary request from here goes
/// straight to the network and answers whenever the phone is online. That
/// said "Protected" for a tunnel that carried nothing (seen 2026-10-06 on a
/// throttled address). Asked through the proxy tun2socks feeds, the request
/// takes the tunnel's own path.
///
/// HTTPS, not plain HTTP: through the server's throttled direct address,
/// plain requests inside the tunnel were answered while every HTTPS page --
/// TLS inside the tunnel's own TLS -- hung after its handshake, and a phone
/// showed "Protected" over a tunnel nobody could browse with (2026-10-14).
/// The certificate is checked: a blockpage answering for the name is not an
/// answer. [onBadCertificate] is for tests only.
Future<bool> answersThroughSocks(
  LocalProxy proxy, {
  String host = 'www.gstatic.com',
  String path = '/generate_204',
  int port = 443,
  Duration timeout = const Duration(seconds: 8),
  bool Function(X509Certificate certificate)? onBadCertificate,
}) async {
  final ({int status, String body})? answer = await httpsThroughSocks(
    proxy,
    host: host,
    path: path,
    port: port,
    timeout: timeout,
    onBadCertificate: onBadCertificate,
    // The status line is all this needs.
    readBody: false,
  );
  return answer != null && answer.status < 400;
}

/// An HTTPS GET of [path] on [host] through [proxy]'s SOCKS5 side: the
/// tunnel's own path, IPv6 addresses included. Null when nothing answered.
///
/// SOCKS rather than the HTTP proxy Dart's [HttpClient] can use: that writes
/// an IPv6 host into CONNECT without brackets, Xray cannot parse it, and the
/// leak test called IPv6 blocked while every app's IPv6 went out through the
/// server.
Future<({int status, String body})?> httpsThroughSocks(
  LocalProxy proxy, {
  required String host,
  required String path,
  int port = 443,
  Duration timeout = const Duration(seconds: 8),
  bool Function(X509Certificate certificate)? onBadCertificate,
  bool readBody = true,
  int bodyLimit = 64 * 1024,
}) async {
  RawSocket? socket;
  RawSecureSocket? secure;
  try {
    return await () async {
      final RawSocket raw = socket = await RawSocket.connect(
        InternetAddress.loopbackIPv4,
        proxy.port,
        timeout: timeout,
      );
      final _Bytes reader = _Bytes();
      final StreamSubscription<RawSocketEvent> events = raw.listen(
        (RawSocketEvent event) => _pump(raw, event, reader),
        onError: (Object _) => reader.close(),
        onDone: reader.close,
      );
      final List<int> user = utf8.encode(proxy.username);
      final List<int> pass = utf8.encode(proxy.password);
      _send(raw, <int>[5, 1, 2]);
      if ((await reader.take(2))[1] != 2) {
        return null;
      }
      _send(raw, <int>[1, user.length, ...user, pass.length, ...pass]);
      if ((await reader.take(2))[1] != 0) {
        return null;
      }
      final InternetAddress? literal = InternetAddress.tryParse(host);
      final List<int> name = utf8.encode(host);
      _send(raw, <int>[
        5,
        1,
        0,
        ...switch (literal?.type) {
          InternetAddressType.IPv4 => <int>[1, ...literal!.rawAddress],
          InternetAddressType.IPv6 => <int>[4, ...literal!.rawAddress],
          _ => <int>[3, name.length, ...name],
        },
        port >> 8,
        port & 0xff,
      ]);
      final List<int> reply = await reader.take(5);
      if (reply[1] != 0) {
        return null;
      }
      // The bound address: the first byte of it is already read.
      await reader.take(switch (reply[3]) {
        1 => 5,
        4 => 17,
        _ => reply[4] + 2,
      });
      final RawSecureSocket tls = secure = await RawSecureSocket.secure(
        raw,
        subscription: events,
        host: host,
        onBadCertificate: onBadCertificate,
      );
      final _Bytes answer = _Bytes();
      tls.listen(
        (RawSocketEvent event) => _pump(tls, event, answer),
        onError: (Object _) => answer.close(),
        onDone: answer.close,
      );
      // HTTP/1.0, so the body arrives whole and then the connection closes:
      // no chunked encoding to undo.
      final String hostHeader = literal?.type == InternetAddressType.IPv6
          ? '[$host]'
          : host;
      _send(
        tls,
        ascii.encode(
          'GET $path HTTP/1.0\r\nHost: $hostHeader\r\nConnection: close\r\n\r\n',
        ),
      );
      final int? status = int.tryParse(
        ascii.decode(await answer.take(12)).substring(9, 12),
      );
      if (status == null) {
        return null;
      }
      if (!readBody) {
        return (status: status, body: '');
      }
      final String rest = utf8.decode(
        await answer.rest(limit: bodyLimit),
        allowMalformed: true,
      );
      final int split = rest.indexOf('\r\n\r\n');
      return (status: status, body: split < 0 ? '' : rest.substring(split + 4));
    }().timeout(timeout);
  } on Object {
    return null;
  } finally {
    secure?.close();
    socket?.close();
  }
}

void _pump(RawSocket socket, RawSocketEvent event, _Bytes into) {
  if (event == RawSocketEvent.read) {
    final Uint8List? data = socket.read();
    if (data != null) {
      into.add(data);
    }
  } else if (event == RawSocketEvent.readClosed ||
      event == RawSocketEvent.closed) {
    into.close();
  }
}

/// Writes all of [bytes]: a few hundred at most, which a fresh loopback
/// socket takes at once.
void _send(RawSocket socket, List<int> bytes) {
  for (int sent = 0; sent < bytes.length;) {
    final int wrote = socket.write(bytes, sent);
    if (wrote == 0) {
      throw const SocketException('the proxy took nothing');
    }
    sent += wrote;
  }
}

/// Dart's [HttpClient.findProxy] answer for [proxy]: Xray's local inbound
/// takes HTTP proxy requests as well as SOCKS5, with the same account. How
/// this app's own measurements reach the tunnel on Android, where the app is
/// kept out of its own VPN and an ordinary request measures the bare line.
String httpProxyDirective(LocalProxy proxy) =>
    'PROXY ${proxy.username}:${proxy.password}@127.0.0.1:${proxy.port}';

/// UDP through [LocalProxy]'s SOCKS5 UDP ASSOCIATE: the path every app's DNS
/// and other UDP takes inside the tunnel.
class SocksUdp {
  SocksUdp._(this._control, this._udp, this._relay, this._relayPort);

  final Socket _control;
  final RawDatagramSocket _udp;
  final InternetAddress _relay;
  final int _relayPort;

  static Future<SocksUdp> open(
    LocalProxy proxy, {
    Duration timeout = const Duration(seconds: 6),
  }) async {
    final Socket control = await Socket.connect(
      InternetAddress.loopbackIPv4,
      proxy.port,
      timeout: timeout,
    );
    try {
      final _Bytes reader = _Bytes.listening(control);
      control.add(<int>[5, 2, 0, 2]);
      final int method = (await reader.take(2).timeout(timeout))[1];
      if (method == 2) {
        final List<int> user = utf8.encode(proxy.username);
        final List<int> pass = utf8.encode(proxy.password);
        control.add(<int>[1, user.length, ...user, pass.length, ...pass]);
        if ((await reader.take(2).timeout(timeout))[1] != 0) {
          throw const SocketException('the proxy refused the account');
        }
      } else if (method != 0) {
        throw const SocketException('no acceptable method');
      }
      control.add(<int>[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]);
      final List<int> reply = await reader.take(4).timeout(timeout);
      if (reply[1] != 0 || reply[3] != 1) {
        throw const SocketException('UDP association refused');
      }
      final List<int> bound = await reader.take(6).timeout(timeout);
      final InternetAddress relay = bound.take(4).every((int b) => b == 0)
          ? InternetAddress.loopbackIPv4
          : InternetAddress.fromRawAddress(
              Uint8List.fromList(bound.sublist(0, 4)),
            );
      final RawDatagramSocket udp = await RawDatagramSocket.bind(
        InternetAddress.loopbackIPv4,
        0,
      );
      return SocksUdp._(control, udp, relay, bound[4] << 8 | bound[5]);
    } on Object {
      control.destroy();
      rethrow;
    }
  }

  /// Sends [payload] to [to]:[port] through the tunnel.
  void send(InternetAddress to, int port, List<int> payload) {
    _udp.send(
      <int>[0, 0, 0, 1, ...to.rawAddress, port >> 8, port & 0xff, ...payload],
      _relay,
      _relayPort,
    );
  }

  /// What comes back, without the SOCKS header.
  ///
  /// A plain transform, not an `async*` generator: cancelling a generator
  /// parked on another stream never completed, and the packet-loss test hung.
  Stream<Uint8List> get payloads => _udp.expand((RawSocketEvent event) {
    final Datagram? datagram = event == RawSocketEvent.read
        ? _udp.receive()
        : null;
    if (datagram == null || datagram.data.length < 5) {
      return const <Uint8List>[];
    }
    final Uint8List d = datagram.data;
    final int header = switch (d[3]) {
      1 => 10,
      4 => 22,
      _ => 7 + d[4],
    };
    return d.length > header
        ? <Uint8List>[d.sublist(header)]
        : const <Uint8List>[];
  });

  void close() {
    _udp.close();
    _control.destroy();
  }
}

/// A DNS question for [name]'s IPv4 addresses (or another record [type]),
/// with id [id].
List<int> dnsQuery(int id, String name, {int type = 1}) => <int>[
  id >> 8, id & 0xff, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
  for (final String label in name.split('.')) ...<int>[
    label.length,
    ...ascii.encode(label),
  ],
  0, type >> 8, type & 0xff, 0, 1, // end of name, type, IN
];

/// The IPv4 addresses in a DNS answer to question [id], or null when [answer]
/// is not that answer or reports an error.
List<InternetAddress>? dnsAnswerAddresses(Uint8List answer, int id) {
  if (answer.length < 12 ||
      (answer[0] << 8 | answer[1]) != id ||
      answer[2] & 0x80 == 0 ||
      answer[3] & 0x0f != 0) {
    return null;
  }
  int at = 12;
  int skipName() {
    while (at < answer.length) {
      final int length = answer[at];
      if (length & 0xc0 == 0xc0) {
        return at += 2;
      }
      at += 1 + length;
      if (length == 0) {
        return at;
      }
    }
    throw const FormatException('truncated name');
  }

  try {
    for (int q = answer[4] << 8 | answer[5]; q > 0; q--) {
      skipName();
      at += 4;
    }
    final List<InternetAddress> addresses = <InternetAddress>[];
    for (int a = answer[6] << 8 | answer[7]; a > 0; a--) {
      skipName();
      final int type = answer[at] << 8 | answer[at + 1];
      final int length = answer[at + 8] << 8 | answer[at + 9];
      at += 10;
      if (type == 1 && length == 4) {
        addresses.add(
          InternetAddress.fromRawAddress(answer.sublist(at, at + 4)),
        );
      }
      at += length;
    }
    return addresses;
  } on Object {
    return null;
  }
}

/// [name]'s IPv4 addresses as [dnsServer] answers them through [proxy] --
/// what an app on this phone gets. Empty when nothing answered.
Future<List<InternetAddress>> lookupThroughSocks(
  LocalProxy proxy,
  InternetAddress dnsServer,
  String name, {
  Duration timeout = const Duration(seconds: 6),
  Random? random,
}) async {
  SocksUdp? udp;
  try {
    return await () async {
      final SocksUdp u = udp = await SocksUdp.open(proxy, timeout: timeout);
      final int id = (random ?? Random.secure()).nextInt(1 << 16);
      u.send(dnsServer, 53, dnsQuery(id, name));
      await for (final Uint8List payload in u.payloads) {
        final List<InternetAddress>? addresses = dnsAnswerAddresses(
          payload,
          id,
        );
        if (addresses != null) {
          return addresses;
        }
      }
      return <InternetAddress>[];
    }().timeout(timeout);
  } on Object {
    return <InternetAddress>[];
  } finally {
    udp?.close();
  }
}

/// Whether a DNS question asked of [dnsServer] through [proxy] over UDP gets
/// an answer -- the path every app's DNS takes in the tunnel.
///
/// [answersThroughSocks] cannot see this: it hands the proxy a name to look
/// up itself, over TCP. A tunnel whose UDP side had stopped answered it fine
/// while no app on the phone could resolve anything.
Future<bool> resolvesThroughSocks(
  LocalProxy proxy,
  InternetAddress dnsServer, {
  String name = 'www.gstatic.com',
  Duration timeout = const Duration(seconds: 6),
  Random? random,
}) async => (await lookupThroughSocks(
  proxy,
  dnsServer,
  name,
  timeout: timeout,
  random: random,
)).isNotEmpty;

/// Bytes read off a socket, handed out exactly as many as asked for.
class _Bytes {
  _Bytes();

  /// Fed by a socket's own listener.
  _Bytes.listening(Socket socket) {
    socket.listen(add, onError: (Object _) => close(), onDone: close);
  }

  final List<int> _buffer = <int>[];
  Completer<void>? _waiting;
  bool _done = false;

  void add(List<int> data) {
    _buffer.addAll(data);
    _wake();
  }

  void close() => _wake(done: true);

  void _wake({bool done = false}) {
    _done = _done || done;
    _waiting?.complete();
    _waiting = null;
  }

  /// Everything until the socket closes, up to [limit] bytes.
  Future<List<int>> rest({required int limit}) async {
    while (!_done && _buffer.length < limit) {
      await (_waiting = Completer<void>()).future;
    }
    final List<int> taken = _buffer.take(limit).toList();
    _buffer.clear();
    return taken;
  }

  Future<List<int>> take(int count) async {
    while (_buffer.length < count) {
      if (_done) {
        throw const SocketException('closed before the answer');
      }
      await (_waiting = Completer<void>()).future;
    }
    final List<int> taken = _buffer.sublist(0, count);
    _buffer.removeRange(0, count);
    return taken;
  }
}
