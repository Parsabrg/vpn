import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/servers/server_repository.dart';
import 'package:nebula_mobile/core/xray/local_proxy.dart';
import 'package:nebula_mobile/core/xray/xray_config.dart';

const LocalProxy _localProxy = LocalProxy(
  port: 20443,
  username: 'n0011223344556677',
  password: '00112233445566778899aabbccddeeff',
);

void main() {
  group('the per-protocol delay probe', () {
    const XrayClientResult ws = XrayClientResult(
      clientId: 'c1',
      uuid: 'a1b2c3d4-0000-0000-0000-000000000000',
      serverAddress: 'cdn.example.test',
      port: 443,
      sni: 'cdn.example.test',
      transport: 'websocket',
      transportSecurity: 'tls',
      adBlock: true,
      path: '/ws',
    );

    test('is exactly the outbound a connection dials, and nothing else', () {
      // No routing: an ad-block or sanctions-only rule would send the test
      // request somewhere other than the server and report the wrong path.
      final Map<String, dynamic> config =
          jsonDecode(renderXrayDelayProbeConfigJson(ws))
              as Map<String, dynamic>;

      expect(config.containsKey('routing'), isFalse);
      expect(config.containsKey('inbounds'), isFalse);
      expect(config.containsKey('dns'), isFalse);
      final Map<String, dynamic> proxy =
          (config['outbounds'] as List<dynamic>).first as Map<String, dynamic>;
      expect(proxy['protocol'], 'vless');
      expect(jsonEncode(proxy), contains('cdn.example.test'));
      expect(jsonEncode(proxy), contains('/ws'));
    });
  });

  group('the local proxy', () {
    // Loopback is shared by every app on the phone. Before this, an app
    // excluded from the tunnel could route through the proxy with no
    // credentials and read the server's address off the answer.
    const XrayClientResult vless = XrayClientResult(
      clientId: 'c1',
      uuid: 'a1b2c3d4-0000-0000-0000-000000000000',
      serverAddress: 'ams-1.example.test',
      port: 443,
      sni: 'ams-1.example.test',
      transport: 'xhttp',
      transportSecurity: 'tls',
      adBlock: false,
      path: '/p',
    );
    const XrayClientResult hysteria = XrayClientResult(
      clientId: 'c2',
      uuid: 'b2c3d4e5-0000-0000-0000-000000000000',
      serverAddress: 'ams-3.example.test',
      port: 8450,
      sni: 'ams-3.example.test',
      transport: 'hysteria',
      transportSecurity: 'tls',
      adBlock: false,
    );

    Map<String, dynamic> socksSettingsOf(String json) {
      final Map<String, dynamic> config =
          jsonDecode(json) as Map<String, dynamic>;
      final List<dynamic> inbounds = config['inbounds'] as List<dynamic>;
      return (inbounds.single as Map<String, dynamic>)['settings']
          as Map<String, dynamic>;
    }

    test('the Xray inbound demands the credentials', () {
      final Map<String, dynamic> settings = socksSettingsOf(
        renderXrayClientConfigJson(vless, localProxy: _localProxy),
      );

      expect(settings['auth'], 'password');
      expect(settings['accounts'], <Map<String, String>>[
        <String, String>{
          'user': _localProxy.username,
          'pass': _localProxy.password,
        },
      ]);
      // UDP still has to cross it: tun2socks relays UDP through the proxy.
      expect(settings['udp'], isTrue);
    });

    test('the Hysteria2 child demands them too', () {
      final String json = renderXrayClientConfigJson(
        hysteria,
        localProxy: _localProxy,
      );
      final String yaml =
          (jsonDecode(json) as Map<String, dynamic>)['nebulaHysteriaConfig']
              as String;

      expect(yaml, contains('  username: "${_localProxy.username}"'));
      expect(yaml, contains('  password: "${_localProxy.password}"'));
      // And the envelope carries them where the plugin reads them for
      // tun2socks, or tun2socks would be refused by its own proxy.
      expect(socksSettingsOf(json)['auth'], 'password');
    });

    test('no rendering leaves it open', () {
      for (final XrayClientResult result in <XrayClientResult>[
        vless,
        hysteria,
      ]) {
        expect(
          renderXrayClientConfigJson(result, localProxy: _localProxy),
          isNot(contains('noauth')),
        );
      }
    });

    test('the inbound listens on the port it was given', () {
      final Map<String, dynamic> config =
          jsonDecode(renderXrayClientConfigJson(vless, localProxy: _localProxy))
              as Map<String, dynamic>;
      final Map<String, dynamic> inbound =
          (config['inbounds'] as List<dynamic>).single as Map<String, dynamic>;

      // Not 10808: that is v2rayNG's default, and a running v2rayNG proxy
      // left this engine unable to bind it.
      expect(inbound['port'], _localProxy.port);
    });

    test('a generated proxy has a free port and fresh credentials', () async {
      final LocalProxy a = await LocalProxy.generate();
      final LocalProxy b = await LocalProxy.generate();

      expect(a.port, inInclusiveRange(1, 65535));

      expect(a.password, isNot(b.password));
      expect(a.password, matches(RegExp(r'^[0-9a-f]{32}$')));
      expect(a.username, matches(RegExp(r'^n[0-9a-f]{16}$')));
    });
  });

  group('renderXrayClientConfigJson', () {
    test('always enables Xray logging so a failed start is diagnosable', () {
      // Without a log block Xray-core emits nothing at all, which is how a
      // Hysteria2 tunnel that never started passed for one that had: the app
      // showed connected, tun0 came up, and the core never said why it sent
      // no packets.
      for (final String transport in <String>['xhttp', 'grpc', 'ws']) {
        final XrayClientResult result = XrayClientResult(
          clientId: 'client-log',
          uuid: 'a1b2c3d4-0000-0000-0000-000000000000',
          serverAddress: 'ams-1.example.test',
          port: 8443,
          sni: 'ams-1.example.test',
          adBlock: false,
          transport: transport,
          transportSecurity: 'tls',
          path: transport == 'ws' ? '/ws-path' : null,
          serviceName: transport == 'grpc' ? 'grpc' : null,
        );

        final Map<String, dynamic> config =
            jsonDecode(
                  renderXrayClientConfigJson(result, localProxy: _localProxy),
                )
                as Map<String, dynamic>;

        final Map<String, dynamic>? log =
            config['log'] as Map<String, dynamic>?;
        expect(log, isNotNull, reason: 'no log block for $transport');
        expect(log!['loglevel'], 'warning');
      }
    });

    test('enables the three things the byte counters need, together', () {
      // The plugin reads Xray's own stats by outbound tag
      // (queryStats("proxy", "downlink")). Three pieces have to line up and
      // any one missing gives zero readings forever, which is indistinguishable
      // on screen from a tunnel nobody used. That is exactly how this shipped
      // the first time.
      for (final String transport in <String>['xhttp', 'grpc', 'ws', 'raw']) {
        final XrayClientResult result = XrayClientResult(
          clientId: 'client-stats',
          uuid: 'a1b2c3d4-0000-0000-0000-000000000000',
          serverAddress: 'ams-1.example.test',
          port: 8443,
          sni: 'ams-1.example.test',
          adBlock: false,
          transport: transport,
          transportSecurity: 'tls',
          path: transport == 'ws' ? '/ws-path' : null,
          serviceName: transport == 'grpc' ? 'grpc' : null,
        );

        final Map<String, dynamic> config =
            jsonDecode(
                  renderXrayClientConfigJson(result, localProxy: _localProxy),
                )
                as Map<String, dynamic>;

        // 1. The core records nothing at all without this.
        expect(config['stats'], isNotNull, reason: 'no stats for $transport');

        // 2. The stats object stays empty unless the counters are named.
        final Map<String, dynamic> system =
            (config['policy'] as Map<String, dynamic>)['system']
                as Map<String, dynamic>;
        expect(system['statsOutboundUplink'], isTrue);
        expect(system['statsOutboundDownlink'], isTrue);

        // 3. The tag the plugin actually queries under.
        final List<dynamic> outbounds = config['outbounds'] as List<dynamic>;
        expect(
          (outbounds.first as Map<String, dynamic>)['tag'],
          'proxy',
          reason: 'untagged outbound for $transport',
        );
      }
    });

    test('the ad-block blackhole keeps its own tag and its routing rule', () {
      // Blocked traffic is not carried, so it is deliberately not counted as
      // proxy traffic -- but the rule that reaches it must still match.
      const XrayClientResult result = XrayClientResult(
        clientId: 'client-adblock',
        uuid: 'a1b2c3d4-0000-0000-0000-000000000000',
        serverAddress: 'ams-1.example.test',
        port: 8443,
        sni: 'ams-1.example.test',
        adBlock: true,
        transport: 'xhttp',
        transportSecurity: 'tls',
      );

      final Map<String, dynamic> config =
          jsonDecode(
                renderXrayClientConfigJson(result, localProxy: _localProxy),
              )
              as Map<String, dynamic>;

      final List<dynamic> outbounds = config['outbounds'] as List<dynamic>;
      final Set<Object?> tags = outbounds
          .map((dynamic o) => (o as Map<String, dynamic>)['tag'])
          .toSet();
      expect(tags, containsAll(<String>['proxy', 'ad-block']));

      final List<dynamic> rules =
          (config['routing'] as Map<String, dynamic>)['rules'] as List<dynamic>;
      expect((rules.first as Map<String, dynamic>)['outboundTag'], 'ad-block');
    });

    test('renders a vless/xhttp/tls outbound with the given peer fields', () {
      const XrayClientResult result = XrayClientResult(
        clientId: 'client-1',
        uuid: 'a1b2c3d4-0000-0000-0000-000000000000',
        serverAddress: 'ams-1.example.test',
        port: 8443,
        sni: 'ams-1.example.test',
        adBlock: false,
        transport: 'xhttp',
        transportSecurity: 'tls',
        path: '/xhttp-path',
      );

      final Map<String, dynamic> config =
          jsonDecode(
                renderXrayClientConfigJson(result, localProxy: _localProxy),
              )
              as Map<String, dynamic>;

      final List<dynamic> outbounds = config['outbounds'] as List<dynamic>;
      final Map<String, dynamic> outbound =
          outbounds.single as Map<String, dynamic>;
      expect(outbound['protocol'], 'vless');

      final Map<String, dynamic> settings =
          outbound['settings'] as Map<String, dynamic>;
      final List<dynamic> vnext = settings['vnext'] as List<dynamic>;
      final Map<String, dynamic> server = vnext.single as Map<String, dynamic>;
      expect(server['address'], 'ams-1.example.test');
      expect(server['port'], 8443);
      final List<dynamic> users = server['users'] as List<dynamic>;
      final Map<String, dynamic> user = users.single as Map<String, dynamic>;
      expect(user['id'], 'a1b2c3d4-0000-0000-0000-000000000000');
      expect(user['encryption'], 'none');

      final Map<String, dynamic> streamSettings =
          outbound['streamSettings'] as Map<String, dynamic>;
      expect(streamSettings['network'], 'xhttp');
      expect(streamSettings['security'], 'tls');
      expect(
        (streamSettings['xhttpSettings'] as Map<String, dynamic>)['path'],
        '/xhttp-path',
      );
      expect(
        (streamSettings['tlsSettings'] as Map<String, dynamic>)['serverName'],
        'ams-1.example.test',
      );

      // The plugin passes this config straight to the native Xray core with
      // no synthesis of its own, so a usable local inbound must be present
      // too, not just the outbound that reaches the real server.
      final List<dynamic> inbounds = config['inbounds'] as List<dynamic>;
      final Map<String, dynamic> inbound =
          inbounds.single as Map<String, dynamic>;
      expect(inbound['protocol'], 'socks');
      expect(inbound['listen'], '127.0.0.1');
    });

    test('omits tlsSettings when the transport is not encrypted', () {
      const XrayClientResult result = XrayClientResult(
        clientId: 'client-1',
        uuid: 'a1b2c3d4-0000-0000-0000-000000000000',
        serverAddress: 'ams-1.example.test',
        port: 80,
        sni: 'ams-1.example.test',
        adBlock: false,
        transport: 'xhttp',
        transportSecurity: 'none',
        path: '/xhttp-path',
      );

      final Map<String, dynamic> config =
          jsonDecode(
                renderXrayClientConfigJson(result, localProxy: _localProxy),
              )
              as Map<String, dynamic>;
      final List<dynamic> outbounds = config['outbounds'] as List<dynamic>;
      final Map<String, dynamic> outbound =
          outbounds.single as Map<String, dynamic>;
      final Map<String, dynamic> streamSettings =
          outbound['streamSettings'] as Map<String, dynamic>;

      expect(streamSettings['security'], 'none');
      expect(streamSettings.containsKey('tlsSettings'), isFalse);
    });

    Map<String, dynamic> tlsSettingsFor(String? caCertificate) {
      final XrayClientResult result = XrayClientResult(
        clientId: 'client-1',
        uuid: 'a1b2c3d4-0000-0000-0000-000000000000',
        serverAddress: '203.0.113.7',
        port: 443,
        sni: '203.0.113.7',
        adBlock: false,
        transport: 'xhttp',
        transportSecurity: 'tls',
        path: '/xhttp-path',
        caCertificate: caCertificate,
      );
      final Map<String, dynamic> config =
          jsonDecode(
                renderXrayClientConfigJson(result, localProxy: _localProxy),
              )
              as Map<String, dynamic>;
      final Map<String, dynamic> outbound =
          (config['outbounds'] as List<dynamic>).first as Map<String, dynamic>;
      return (outbound['streamSettings'] as Map<String, dynamic>)['tlsSettings']
          as Map<String, dynamic>;
    }

    test('an installation with its own CA is verified against it', () {
      // Seen on a phone: without it Xray checked only the system's roots, the
      // TLS handshake failed, and the app said Protected with nothing moving.
      const String ca =
          '-----BEGIN CERTIFICATE-----\nTmVidWxh\nIHRlc3Q=\n-----END CERTIFICATE-----\n';

      final Map<String, dynamic> tls = tlsSettingsFor(ca);

      expect(tls['serverName'], '203.0.113.7');
      expect(tls['certificates'], <Map<String, dynamic>>[
        <String, dynamic>{
          'usage': 'verify',
          'certificate': <String>[
            '-----BEGIN CERTIFICATE-----',
            'TmVidWxh',
            'IHRlc3Q=',
            '-----END CERTIFICATE-----',
          ],
        },
      ]);
      expect(tls.containsKey('allowInsecure'), isFalse);
      // That CA only: a publicly trusted certificate for the same address
      // must not pass, just as it would not when pairing.
      expect(tls['disableSystemRoot'], isTrue);
    });

    // Xray's own handshake is easy to single out; Chrome's is everywhere.
    test('looks like Chrome to the network', () {
      expect(tlsSettingsFor(null)['fingerprint'], 'chrome');
    });

    test('an installation with its own CA keeps the default handshake', () {
      expect(
        tlsSettingsFor(
          '-----BEGIN CERTIFICATE-----\nTmVidWxh\n-----END CERTIFICATE-----\n',
        ).containsKey('fingerprint'),
        isFalse,
      );
    });

    test('a publicly trusted server adds no certificate', () {
      final Map<String, dynamic> tls = tlsSettingsFor(null);

      expect(tls.containsKey('certificates'), isFalse);
      expect(tls.containsKey('disableSystemRoot'), isFalse);
    });

    test('renders a grpc outbound with the service name', () {
      const XrayClientResult result = XrayClientResult(
        clientId: 'client-1',
        uuid: 'a1b2c3d4-0000-0000-0000-000000000000',
        serverAddress: 'ams-1.example.test',
        port: 8447,
        sni: 'ams-1.example.test',
        adBlock: false,
        transport: 'grpc',
        transportSecurity: 'tls',
        serviceName: 'grpc',
      );

      final Map<String, dynamic> config =
          jsonDecode(
                renderXrayClientConfigJson(result, localProxy: _localProxy),
              )
              as Map<String, dynamic>;
      final Map<String, dynamic> outbound =
          (config['outbounds'] as List<dynamic>).single as Map<String, dynamic>;
      final Map<String, dynamic> streamSettings =
          outbound['streamSettings'] as Map<String, dynamic>;

      expect(streamSettings['network'], 'grpc');
      expect(
        (streamSettings['grpcSettings'] as Map<String, dynamic>)['serviceName'],
        'grpc',
      );
    });

    test('renders a websocket outbound with the path', () {
      const XrayClientResult result = XrayClientResult(
        clientId: 'client-1',
        uuid: 'a1b2c3d4-0000-0000-0000-000000000000',
        serverAddress: 'ams-1.example.test',
        port: 8448,
        sni: 'ams-1.example.test',
        adBlock: false,
        transport: 'websocket',
        transportSecurity: 'tls',
        path: '/ws',
      );

      final Map<String, dynamic> config =
          jsonDecode(
                renderXrayClientConfigJson(result, localProxy: _localProxy),
              )
              as Map<String, dynamic>;
      final Map<String, dynamic> outbound =
          (config['outbounds'] as List<dynamic>).single as Map<String, dynamic>;
      final Map<String, dynamic> streamSettings =
          outbound['streamSettings'] as Map<String, dynamic>;

      expect(streamSettings['network'], 'websocket');
      expect(
        (streamSettings['wsSettings'] as Map<String, dynamic>)['path'],
        '/ws',
      );
    });

    test('renders a raw tcp outbound with no per-transport settings block', () {
      const XrayClientResult result = XrayClientResult(
        clientId: 'client-1',
        uuid: 'a1b2c3d4-0000-0000-0000-000000000000',
        serverAddress: 'ams-1.example.test',
        port: 8449,
        sni: 'ams-1.example.test',
        adBlock: false,
        transport: 'raw',
        transportSecurity: 'tls',
      );

      final Map<String, dynamic> config =
          jsonDecode(
                renderXrayClientConfigJson(result, localProxy: _localProxy),
              )
              as Map<String, dynamic>;
      final Map<String, dynamic> outbound =
          (config['outbounds'] as List<dynamic>).single as Map<String, dynamic>;
      final Map<String, dynamic> streamSettings =
          outbound['streamSettings'] as Map<String, dynamic>;

      expect(streamSettings['network'], 'raw');
      expect(streamSettings.containsKey('wsSettings'), isFalse);
      expect(streamSettings.containsKey('grpcSettings'), isFalse);
      expect(streamSettings.containsKey('xhttpSettings'), isFalse);
    });

    test('hysteria renders a config for the reference client, not for Xray', () {
      // Xray accepts Salamander obfuscation and silently discards it: a client
      // offering a deliberately wrong password authenticates, so a server
      // configured for obfuscation has none. Measured against the live server;
      // see docs/adr/0003. This transport therefore runs the reference binary
      // as a child process instead.
      const XrayClientResult result = XrayClientResult(
        clientId: 'client-1',
        uuid: 'a1b2c3d4-0000-0000-0000-000000000000',
        serverAddress: '203.0.113.10',
        port: 8450,
        sni: 'ams-1.example.test',
        adBlock: false,
        transport: 'hysteria',
        transportSecurity: 'tls',
        obfsPassword: 's3cret-salamander',
      );

      final Map<String, dynamic> config =
          jsonDecode(
                renderXrayClientConfigJson(result, localProxy: _localProxy),
              )
              as Map<String, dynamic>;
      final String yaml = config['nebulaHysteriaConfig'] as String;

      expect(yaml, contains('server: 203.0.113.10:8450'));
      // The client UUID is the whole credential; the server renders it as both
      // username and password in its own userpass map.
      expect(
        yaml,
        contains(
          'auth: a1b2c3d4-0000-0000-0000-000000000000:'
          'a1b2c3d4-0000-0000-0000-000000000000',
        ),
      );
      expect(yaml, contains('sni: ams-1.example.test'));
      expect(yaml, contains('type: salamander'));
      expect(yaml, contains('password: s3cret-salamander'));
      // Certificate verification stays on -- the server presents a real
      // certificate for this name, and accepting any would give up the only
      // thing stopping an interceptor impersonating it.
      expect(yaml, contains('insecure: false'));
    });

    test('hysteria listens on the port tun2socks dials', () {
      // These two must agree or the tunnel is silently dead: tun2socks dials a
      // fixed local port and whichever engine is running has to be listening
      // on it.
      const XrayClientResult result = XrayClientResult(
        clientId: 'client-1',
        uuid: 'a1b2c3d4-0000-0000-0000-000000000000',
        serverAddress: '203.0.113.10',
        port: 8450,
        sni: 'ams-1.example.test',
        adBlock: false,
        transport: 'hysteria',
        transportSecurity: 'tls',
      );

      final Map<String, dynamic> config =
          jsonDecode(
                renderXrayClientConfigJson(result, localProxy: _localProxy),
              )
              as Map<String, dynamic>;
      final Map<String, dynamic> inbound =
          (config['inbounds'] as List<dynamic>).single as Map<String, dynamic>;
      final int socksPort = inbound['port'] as int;

      expect(
        config['nebulaHysteriaConfig'] as String,
        contains('listen: 127.0.0.1:$socksPort'),
      );
    });

    test('hysteria still declares the tunnel DNS servers', () {
      // Read by the plugin into VpnService.Builder.addDnsServer. Absent,
      // Android falls back to the underlying network's resolver, which on the
      // target network forges answers -- sending a client to a blockpage
      // address before any tunnelled connection is attempted.
      const XrayClientResult result = XrayClientResult(
        clientId: 'client-1',
        uuid: 'a1b2c3d4-0000-0000-0000-000000000000',
        serverAddress: '203.0.113.10',
        port: 8450,
        sni: 'ams-1.example.test',
        adBlock: false,
        transport: 'hysteria',
        transportSecurity: 'tls',
      );

      final Map<String, dynamic> config =
          jsonDecode(
                renderXrayClientConfigJson(result, localProxy: _localProxy),
              )
              as Map<String, dynamic>;
      expect(config['dns'], isNotNull);
      final List<dynamic> servers =
          (config['dns'] as Map<String, dynamic>)['servers'] as List<dynamic>;
      expect(servers, isNotEmpty);
    });

    test('adds an ad-block dns module when adBlock is true', () {
      const XrayClientResult result = XrayClientResult(
        clientId: 'client-1',
        uuid: 'a1b2c3d4-0000-0000-0000-000000000000',
        serverAddress: 'ams-1.example.test',
        port: 8443,
        sni: 'ams-1.example.test',
        adBlock: true,
        transport: 'xhttp',
        transportSecurity: 'tls',
        path: '/xhttp-path',
      );

      final Map<String, dynamic> config =
          jsonDecode(
                renderXrayClientConfigJson(result, localProxy: _localProxy),
              )
              as Map<String, dynamic>;

      final Map<String, dynamic> dns = config['dns'] as Map<String, dynamic>;
      expect(dns['servers'], <String>['94.140.14.14']);
    });

    test('a plain profile still declares a resolver, unfiltered', () {
      const XrayClientResult result = XrayClientResult(
        clientId: 'client-1',
        uuid: 'a1b2c3d4-0000-0000-0000-000000000000',
        serverAddress: 'ams-1.example.test',
        port: 8443,
        sni: 'ams-1.example.test',
        adBlock: false,
        transport: 'xhttp',
        transportSecurity: 'tls',
        path: '/xhttp-path',
      );

      final Map<String, dynamic> config =
          jsonDecode(
                renderXrayClientConfigJson(result, localProxy: _localProxy),
              )
              as Map<String, dynamic>;

      // Leaving this unset does not mean "no DNS" -- the plugin then adds no
      // DNS server to the tunnel and Android falls back to the underlying
      // network's resolver, which on a hostile network both observes and
      // forges queries. Confirmed live: with no dns block the tunnel reported
      // an empty DnsAddresses list and a forged answer came back.
      final Map<String, dynamic> dns = config['dns'] as Map<String, dynamic>;
      expect(dns['servers'], <String>['94.140.14.140']);
    });

    test('the deployment\'s own resolvers are used when it names them', () {
      const XrayClientResult result = XrayClientResult(
        clientId: 'client-1',
        uuid: 'a1b2c3d4-0000-0000-0000-000000000000',
        serverAddress: 'ams-1.example.test',
        port: 8443,
        sni: 'ams-1.example.test',
        adBlock: false,
        transport: 'xhttp',
        transportSecurity: 'tls',
        path: '/xhttp-path',
        clientDns: <String>['9.9.9.9', '2620:fe::fe', '1.1.1.1'],
      );

      final Map<String, dynamic> config =
          jsonDecode(
                renderXrayClientConfigJson(result, localProxy: _localProxy),
              )
              as Map<String, dynamic>;

      // IPv6 dropped for the reason the built-in fallback is IPv4 only.
      expect((config['dns'] as Map<String, dynamic>)['servers'], <String>[
        '9.9.9.9',
        '1.1.1.1',
      ]);
    });

    test(
      'ad-block routes ad domains to a blackhole that DNS cannot bypass',
      () {
        const XrayClientResult result = XrayClientResult(
          clientId: 'client-1',
          uuid: 'a1b2c3d4-0000-0000-0000-000000000000',
          serverAddress: 'ams-1.example.test',
          port: 8443,
          sni: 'ams-1.example.test',
          adBlock: true,
          transport: 'xhttp',
          transportSecurity: 'tls',
          path: '/xhttp-path',
        );

        final Map<String, dynamic> config =
            jsonDecode(
                  renderXrayClientConfigJson(result, localProxy: _localProxy),
                )
                as Map<String, dynamic>;

        // Sniffing is what gives the routing rules a hostname to match --
        // tun2socks hands Xray packets addressed by IP, so without it the
        // domain rules below would never fire.
        final Map<String, dynamic> inbound =
            (config['inbounds'] as List<dynamic>).single
                as Map<String, dynamic>;
        final Map<String, dynamic> sniffing =
            inbound['sniffing'] as Map<String, dynamic>;
        expect(sniffing['enabled'], isTrue);
        // QUIC included: without it, anything reached over UDP 443 --
        // much of Chrome's and YouTube's traffic -- never gives the ad-block
        // rule a hostname, and passes straight through it.
        expect(sniffing['destOverride'], <String>['http', 'tls', 'quic']);

        // The real outbound must stay first: Xray treats outbounds[0] as the
        // default route, so a blackhole in that position would drop everything.
        final List<dynamic> outbounds = config['outbounds'] as List<dynamic>;
        expect((outbounds.first as Map<String, dynamic>)['protocol'], 'vless');
        final Map<String, dynamic> blackhole =
            outbounds.last as Map<String, dynamic>;
        expect(blackhole['protocol'], 'blackhole');
        expect(blackhole['tag'], 'ad-block');

        final Map<String, dynamic> routing =
            config['routing'] as Map<String, dynamic>;
        final Map<String, dynamic> rule =
            (routing['rules'] as List<dynamic>).single as Map<String, dynamic>;
        expect(rule['outboundTag'], 'ad-block');
        expect(rule['domain'], contains('domain:doubleclick.net'));
      },
    );

    test('a plain profile has no blackhole, routing, or sniffing overhead', () {
      const XrayClientResult result = XrayClientResult(
        clientId: 'client-1',
        uuid: 'a1b2c3d4-0000-0000-0000-000000000000',
        serverAddress: 'ams-1.example.test',
        port: 8443,
        sni: 'ams-1.example.test',
        adBlock: false,
        transport: 'xhttp',
        transportSecurity: 'tls',
        path: '/xhttp-path',
      );

      final Map<String, dynamic> config =
          jsonDecode(
                renderXrayClientConfigJson(result, localProxy: _localProxy),
              )
              as Map<String, dynamic>;

      expect(config.containsKey('routing'), isFalse);
      expect((config['outbounds'] as List<dynamic>).length, 1);
      final Map<String, dynamic> inbound =
          (config['inbounds'] as List<dynamic>).single as Map<String, dynamic>;
      expect(inbound.containsKey('sniffing'), isFalse);
    });
  });
}
