import 'dart:async';
import 'dart:io';

import '../tunnel/tunnel_traffic.dart';
import 'linux_tunnel_config.dart';

/// The root helper for the Linux tunnel, run through pkexec -- the
/// desktop's own password prompt -- as the Windows supervisor is run through
/// UAC.
///
/// Arguments: engine, config, state directory, owner pid, owner start time,
/// comma-separated DNS servers, and 1 for the kill switch (see the script). The engine is the bundled xray's or
/// hysteria's path, or `wireguard` for the kernel's WireGuard set up with
/// `wg`. Every argument is
/// checked before anything runs as root: the engine must be this app's
/// xray, the config and state must belong to the person who asked, the DNS
/// servers and WireGuard addresses must be addresses.
///
/// It brings up the `nebula` interface, routes everything without the
/// tunnel's mark into it (xray and Hysteria2: everything, IPv4 and IPv6,
/// Hysteria2's server kept out by a rule as it cannot mark its socket;
/// WireGuard: its AllowedIPs, with IPv6 blocked when they carry none, so
/// nothing leaves by v6 around it), and points the system's DNS at the tunnel. Then it waits,
/// and ends the session -- undoing all of it -- when the app asks (a `stop`
/// file), when the engine or interface goes, or when the app itself is gone.
/// Files it leaves for the app, in [linuxSessionOutputs] (root's, not the
/// person's): xray.pid (the engine, or the helper itself for WireGuard),
/// routes-ready, handshake (WireGuard's latest, as Unix seconds),
/// startup.error, runtime.error, stopped.
///
/// The .deb installs it root-owned as [linuxInstalledHelper] with a polkit
/// action of its own, so the prompt names Nebula VPN; that copy runs only
/// the engines installed beside it. Elsewhere (a portable folder) the app
/// writes it to its temp folder and runs it through /bin/bash, trusting that
/// folder as much as the person's account does.
///
const String linuxInstalledHelper = '/usr/lib/nebula-vpn/nebula-vpn-helper';

/// Where the root helper leaves its files for the session in [state]: a
/// folder only root can change, so a link planted in the person's own
/// folder can never redirect a write made as root.
String linuxSessionOutputs(String state) =>
    '/run/nebula-vpn-out/${state.split('/').last}';

/// The engine the installed helper insists on.
const String linuxInstalledEngine =
    '/opt/nebula-vpn/data/flutter_assets/assets/linux_runtime/xray';

/// The helper's engine argument for WireGuard.
const String linuxWireGuardEngine = 'wireguard';

const String linuxVpnSupervisorScript = r'''#!/bin/bash
set -u
ENGINE="$1"; CONFIG="$2"; STATE="$3"; OWNER="$4"; OWNER_START="$5"; DNS="$6"; KILL="${7:-0}"
DEV=nebula
MARK=51888
TABLE=51888
child=""
created=""
routed=""
server_ip=""
run_config=""
wg_config=""
dns_mode=""
saved_link=""
saved_conf=""
guarded=""
blocking=""

fail() { printf '%s' "$1" > "$OUT/startup.error"; exit 1; }

# --- checks, before anything runs as root -------------------------------
[ -d "$STATE" ] && [ ! -L "$STATE" ] || exit 1
owner_uid="${PKEXEC_UID:-}"
[ -n "$owner_uid" ] && [ "$(stat -c %u "$STATE")" = "$owner_uid" ] || exit 1
# What root writes goes to a folder only root can change, never the
# person's own: there a link planted under a known name would have root
# overwrite whatever it points at. The app reads it from here; the one
# thing it writes, the stop request, root only checks for.
session="$(basename "$STATE")"
[[ "$session" =~ ^[A-Za-z0-9._-]{1,80}$ ]] || exit 1
OUT_ROOT=/run/nebula-vpn-out
[ -L "$OUT_ROOT" ] && exit 1
install -d -m 755 -o root -g root "$OUT_ROOT" || exit 1
find "$OUT_ROOT" -mindepth 1 -maxdepth 1 -mmin +1440 -exec rm -rf {} + 2>/dev/null
OUT="$OUT_ROOT/$session"
rm -rf "$OUT"
install -d -m 755 -o root -g root "$OUT" || exit 1
[[ "$OWNER" =~ ^[0-9]+$ ]] && [[ "$OWNER_START" =~ ^[0-9]+$ ]] || exit 1
[ -f "$CONFIG" ] && [ ! -L "$CONFIG" ] || fail "Linux could not find the VPN configuration."
[ "$(dirname "$CONFIG")" = "$STATE" ] || fail "Linux refused an unexpected VPN configuration."
[ "$KILL" = 0 ] || [ "$KILL" = 1 ] || exit 1
if [ "$KILL" = 1 ] && ! command -v nft > /dev/null 2>&1; then
  fail "Linux needs nftables for the kill switch. Install nftables, or turn the kill switch off."
fi
for d in ${DNS//,/ }; do
  [[ "$d" =~ ^[0-9a-fA-F:.]+$ ]] || fail "Linux refused a DNS server that is not an address."
done
engine_name="$(basename "$ENGINE")"
if [ "$ENGINE" = wireguard ]; then
  command -v wg > /dev/null 2>&1 || fail "Linux needs WireGuard tools for this protocol. Install the wireguard-tools package."
else
  case "$engine_name" in xray|hysteria) ;; *) fail "Linux refused an unexpected VPN engine." ;; esac
  [ -x "$ENGINE" ] || fail "Linux could not find the VPN engine."
  if [ "$0" = /usr/lib/nebula-vpn/nebula-vpn-helper ] && [ "$ENGINE" != "/opt/nebula-vpn/data/flutter_assets/assets/linux_runtime/$engine_name" ]; then
    fail "Linux refused an unexpected VPN engine."
  fi
fi

owner_alive() {
  [ -r "/proc/$OWNER/stat" ] || return 1
  # Field 22 is the start time: a pid reused by another process differs.
  [ "$(awk '{print $22}' "/proc/$OWNER/stat" 2>/dev/null)" = "$OWNER_START" ]
}

# Hysteria's TUN adds an IPv6 rule for its own interface, to a table of its
# own, even with no routes asked of it, and leaves it behind (measured).
# Only this tunnel's interface has this name.
drop_interface_rules() {
  for v in -4 -6; do
    ip "$v" rule show 2>/dev/null \
      | sed -n "s/^\([0-9]*\):.* oif $DEV .*lookup \([0-9][0-9]*\).*/\1 \2/p" \
      | while read -r prio table; do
          ip "$v" rule del priority "$prio" oif "$DEV" 2>/dev/null
          [ "$table" -gt 255 ] && ip "$v" route flush table "$table" 2>/dev/null
        done
  done
}

cleanup() {
  if [ -n "$child" ]; then
    kill "$child" 2>/dev/null
    wait "$child" 2>/dev/null
  fi
  if [ -n "$routed" ]; then
    [ -n "$server_ip" ] && ip rule del to "$server_ip" lookup main priority 8999 2>/dev/null
    for v in -4 -6; do
      ip "$v" rule del priority 9000 2>/dev/null
      ip "$v" rule del priority 9001 2>/dev/null
      ip "$v" route flush table "$TABLE" 2>/dev/null
    done
  fi
  [ -n "$created" ] && ip link del "$DEV" 2>/dev/null
  [ -n "$child" ] && drop_interface_rules
  if [ "$dns_mode" = resolvconf ]; then
    if [ -n "$saved_link" ]; then
      ln -sfn "$saved_link" /etc/resolv.conf
    else
      printf '%s\n' "$saved_conf" > /etc/resolv.conf
    fi
  fi
  [ -n "$guarded" ] && nft delete table inet nebula_vpn 2>/dev/null
  [ -n "$blocking" ] && nft delete table inet nebula_killswitch 2>/dev/null
  rm -f "$run_config" "$wg_config"
  # systemd-resolved forgets the interface's DNS when the interface goes.
  touch "$OUT/stopped"
}
trap cleanup EXIT
trap 'exit 0' TERM INT HUP

# Root reads the config once, into a file only root can open, and refuses
# one that names log files: xray running as root would write them anywhere.
# Hysteria reads its config's format from the name.
suffix=.json
[ "$engine_name" = hysteria ] && suffix=.yaml
run_config="$(mktemp --suffix="$suffix" /run/nebula-vpn-XXXXXX)" || fail "Linux could not prepare the VPN configuration."
cat "$CONFIG" > "$run_config"
if grep -Eo '"(access|error)"[[:space:]]*:[[:space:]]*"[^"]*"' "$run_config" | grep -Evq ':[[:space:]]*"(none)?"$'; then
  fail "Linux refused an unexpected VPN configuration."
fi

# --- the interface ------------------------------------------------------
# Any left by a session that ended without its cleanup.
drop_interface_rules
if [ "$ENGINE" = wireguard ]; then
  addresses=""; routes=""
  while IFS='=' read -r key value; do
    key="$(printf '%s' "$key" | tr -d '[:space:]' | tr 'A-Z' 'a-z')"
    value="$(printf '%s' "$value" | tr -d '[:space:]')"
    case "$key" in
      address) addresses="$addresses ${value//,/ }" ;;
      allowedips) routes="$routes ${value//,/ }" ;;
    esac
  done < "$run_config"
  for a in $addresses $routes; do
    [[ "$a" =~ ^[0-9a-fA-F:.]+/[0-9]{1,3}$ ]] || fail "Linux refused a WireGuard address that is not an address."
  done
  [ -n "$addresses" ] && [ -n "$routes" ] || fail "Linux refused an incomplete WireGuard configuration."
  # What `wg` reads: the config without the keys only wg-quick knows.
  wg_config="$(mktemp /run/nebula-vpn-XXXXXX)" || fail "Linux could not prepare the VPN configuration."
  grep -Eiv '^[[:space:]]*(Address|DNS|MTU|Table|PreUp|PostUp|PreDown|PostDown|SaveConfig|ExcludedApplications)[[:space:]]*=' "$run_config" > "$wg_config"
  ip link add "$DEV" type wireguard || fail "Linux could not create the WireGuard interface. The kernel may lack WireGuard."
  created=1
  wg setconf "$DEV" "$wg_config" || fail "Linux could not apply the WireGuard configuration."
  wg set "$DEV" fwmark "$MARK" || fail "Linux could not apply the WireGuard configuration."
  for a in $addresses; do
    ip addr add "$a" dev "$DEV" || fail "Linux could not configure the VPN interface."
  done
  ip link set "$DEV" mtu 1420 up || fail "Linux could not configure the VPN interface."
  # The helper stands in for the engine: the kernel runs WireGuard.
  printf '%s' "$$" > "$OUT/xray.pid"
else
  routes="0.0.0.0/0 ::/0"
  if [ "$engine_name" = hysteria ]; then
    # Hysteria cannot mark its socket, so the server's own address -- the
    # one the app pinned on the server line -- is kept out by a rule.
    server_ip="$(sed -n 's/^server:[[:space:]]*\([0-9.]*\):[0-9]*[[:space:]]*$/\1/p' "$run_config" | head -1)"
    [[ "$server_ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || fail "Linux refused a VPN server that is not an address."
    # Its TUN gives itself its address; the routes are the helper's.
    "$ENGINE" client -c "$run_config" > "$OUT/engine.out" 2> "$OUT/engine.err" &
  else
    # pkexec starts in root's home: the geo files are found beside the engine.
    XRAY_LOCATION_ASSET="$(dirname "$ENGINE")" "$ENGINE" run -format=json -c "$run_config" > "$OUT/engine.out" 2> "$OUT/engine.err" &
  fi
  child=$!
  printf '%s' "$child" > "$OUT/xray.pid"
  for _ in $(seq 1 80); do
    ip link show "$DEV" > /dev/null 2>&1 && break
    kill -0 "$child" 2>/dev/null || fail "Linux could not connect to the VPN server."
    sleep 0.25
  done
  ip link show "$DEV" > /dev/null 2>&1 || fail "Linux did not create the Nebula VPN interface."
  if [ "$engine_name" = xray ]; then
    ip addr add 172.19.0.1/30 dev "$DEV" || fail "Linux could not configure the VPN interface."
    ip -6 addr add fd00:19::1/64 dev "$DEV" 2>/dev/null
  fi
  ip link set "$DEV" up || fail "Linux could not configure the VPN interface."
fi

# --- routes -------------------------------------------------------------
if [ -n "$routes" ]; then
  routed=1
  if [ -n "$server_ip" ]; then
    ip rule add to "$server_ip" lookup main priority 8999 || fail "Linux could not configure the VPN routes."
  fi
  v6=""
  for r in $routes; do
    if [[ "$r" == *:* ]]; then
      ip -6 route add "$r" dev "$DEV" table "$TABLE" 2>/dev/null && v6=1
    else
      ip route add "$r" dev "$DEV" table "$TABLE" || fail "Linux could not configure the VPN routes."
    fi
  done
  # A tunnel without IPv6 still takes it: unreachable, rather than around it.
  [ -z "$v6" ] && ip -6 route add unreachable default table "$TABLE" 2>/dev/null && v6=1
  ip rule add table main suppress_prefixlength 0 priority 9000 || fail "Linux could not configure the VPN routes."
  ip rule add not fwmark "$MARK" table "$TABLE" priority 9001 || fail "Linux could not configure the VPN routes."
  if [ -n "$v6" ]; then
    ip -6 rule add table main suppress_prefixlength 0 priority 9000 2>/dev/null
    ip -6 rule add not fwmark "$MARK" table "$TABLE" priority 9001 2>/dev/null
  fi
fi

# --- DNS ----------------------------------------------------------------
# systemd-resolved only decides lookups when resolv.conf is its stub; WSL and
# some distros run it beside a resolv.conf of their own.
if command -v resolvectl > /dev/null 2>&1 \
  && systemctl is-active --quiet systemd-resolved 2>/dev/null \
  && grep -q '^nameserver 127\.0\.0\.53' /etc/resolv.conf 2>/dev/null; then
  resolvectl dns "$DEV" ${DNS//,/ } && resolvectl domain "$DEV" '~.' \
    && resolvectl default-route "$DEV" yes 2>/dev/null
  dns_mode=resolved
else
  dns_mode=resolvconf
fi
our_conf="$(for d in ${DNS//,/ }; do echo "nameserver $d"; done)"
# Whatever manages resolv.conf (NetworkManager on a network change, WSL when
# a session starts -- measured) may write it again mid-session, which would
# send lookups around the tunnel. Its version becomes the one put back at
# the end, and the tunnel's goes back in. A symlinked resolv.conf belongs to
# that manager: the link is set aside and put back, never written through.
claim_resolv_conf() {
  if [ -L /etc/resolv.conf ]; then
    saved_link="$(readlink /etc/resolv.conf)"; saved_conf=""
    rm -f /etc/resolv.conf
  elif [ "$(cat /etc/resolv.conf 2>/dev/null)" != "$our_conf" ]; then
    saved_conf="$(cat /etc/resolv.conf 2>/dev/null)"; saved_link=""
  else
    return
  fi
  printf '%s\n' "$our_conf" > /etc/resolv.conf
}
[ "$dns_mode" = resolvconf ] && claim_resolv_conf

# Until the line above runs again, a rewritten resolv.conf names another
# resolver -- WSL's sits on the loopback, where no route reaches. So while
# the tunnel is up, DNS may only go to the tunnel's resolvers (and the
# systemd-resolved stub, which forwards to them); the engines' own marked
# traffic is theirs. Without nftables this guard is skipped.
if command -v nft > /dev/null 2>&1; then
  v4=""; v6=""
  for d in ${DNS//,/ } 127.0.0.53; do
    if [[ "$d" == *:* ]]; then v6="$v6${v6:+, }$d"; else v4="$v4${v4:+, }$d"; fi
  done
  v6_line=""
  [ -n "$v6" ] && v6_line="ip6 daddr { $v6 } accept"
  nft delete table inet nebula_vpn 2>/dev/null
  if nft -f - <<NFT
table inet nebula_vpn {
  chain output {
    type filter hook output priority 0; policy accept;
    meta mark $MARK accept
    ip daddr { $v4 } accept
    $v6_line
    udp dport 53 drop
    tcp dport 53 drop
  }
}
NFT
  then
    guarded=1
  fi
fi

# The kill switch: while the session lasts -- the tunnel up, or gone and
# waiting for the app to reconnect or disconnect -- nothing leaves except
# through the tunnel, the engines' own (marked) traffic, the server's
# address (Hysteria cannot mark its socket), the local network and DHCP.
if [ "$KILL" = 1 ]; then
  local_v4="10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255"
  server_line=""
  [ -n "$server_ip" ] && server_line="ip daddr $server_ip accept"
  nft delete table inet nebula_killswitch 2>/dev/null
  nft -f - <<NFT || fail "Linux could not turn on the kill switch."
table inet nebula_killswitch {
  chain output {
    type filter hook output priority 0; policy drop;
    oif "lo" accept
    meta mark $MARK accept
    oifname "$DEV" accept
    ip daddr { $local_v4 } accept
    ip6 daddr { fe80::/10, ff00::/8 } accept
    udp dport { 67, 68 } accept
    $server_line
  }
}
NFT
  blocking=1
fi

# A tunnel that dies: without the kill switch the session ends and the
# routes go; with it, the block stays until the app reconnects (stopping
# this session first) or disconnects, or is gone.
tunnel_lost() {
  printf '%s' "$1" > "$OUT/runtime.error"
  [ -n "$blocking" ] || exit 1
  while [ ! -e "$STATE/stop" ] && owner_alive; do sleep 0.5; done
  exit 1
}

touch "$OUT/routes-ready"
while true; do
  [ -e "$STATE/stop" ] && exit 0
  owner_alive || exit 0
  [ "$dns_mode" = resolvconf ] && claim_resolv_conf
  if [ -n "$child" ]; then
    if ! kill -0 "$child" 2>/dev/null; then
      tunnel_lost "The VPN engine stopped."
    fi
  else
    if ! ip link show "$DEV" > /dev/null 2>&1; then
      tunnel_lost "The VPN interface went away."
    fi
    # Only root may read it; the app needs it to tell a live tunnel.
    wg show "$DEV" latest-handshakes 2>/dev/null | awk '{print $2; exit}' > "$OUT/handshake"
  fi
  sleep 0.5
done
''';

/// Whether the tunnel's interface exists and is up.
Future<bool> linuxTunnelUp() async {
  try {
    final String state = await File(
      '/sys/class/net/$linuxTunnelInterface/operstate',
    ).readAsString();
    // A TUN or WireGuard interface reports "unknown" when up: it has no
    // carrier to sense.
    return state.trim() == 'up' || state.trim() == 'unknown';
  } on FileSystemException {
    return false;
  }
}

/// The tunnel interface's byte counters, from sysfs.
Future<TunnelTraffic?> linuxTunnelTraffic() async {
  try {
    const String base = '/sys/class/net/$linuxTunnelInterface/statistics';
    final int rx = int.parse(
      (await File('$base/rx_bytes').readAsString()).trim(),
    );
    final int tx = int.parse(
      (await File('$base/tx_bytes').readAsString()).trim(),
    );
    return TunnelTraffic(rxBytes: rx, txBytes: tx);
  } on Object {
    return null;
  }
}

/// A folder only this user can enter: it holds a credential.
Future<Directory> linuxPrivateTemp(String prefix) async {
  final Directory dir = await Directory.systemTemp.createTemp(prefix);
  await Process.run('chmod', <String>['700', dir.path]);
  return dir;
}

/// Starts the root helper through pkexec for [engine] -- the bundled
/// xray's path, or [linuxWireGuardEngine] -- with [config], which must sit
/// in a folder from [linuxPrivateTemp], and returns once its routes are up.
/// Throws with a message for the person when they are not.
Future<void> startLinuxVpnHelper({
  required String engine,
  required File config,
  required List<String> dnsServers,
  bool killSwitch = false,
}) async {
  final Directory state = config.parent;
  final String run =
      engine != linuxWireGuardEngine &&
          Platform.environment.containsKey('APPIMAGE')
      ? await _copyOutOfAppImage(engine, state)
      : engine;
  // The installed app's helper, whose prompt names Nebula VPN; a portable
  // folder brings its own copy.
  final bool installed =
      (engine == linuxInstalledEngine ||
          Platform.resolvedExecutable.startsWith('/opt/nebula-vpn/')) &&
      await File(linuxInstalledHelper).exists();
  final List<String> command;
  if (installed) {
    command = <String>[linuxInstalledHelper];
  } else {
    final File script = File('${state.path}/supervisor.sh');
    await script.writeAsString(linuxVpnSupervisorScript);
    command = <String>['/bin/bash', script.path];
  }
  final Process helper;
  try {
    // Not detached: its exit code says whether the prompt was dismissed.
    // The helper outlives the app regardless and ends the session itself
    // when the app is gone.
    helper = await Process.start('pkexec', <String>[
      ...command,
      run,
      config.path,
      state.path,
      '$pid',
      await _processStartTime(pid),
      dnsServers.join(','),
      if (killSwitch) '1' else '0',
    ]);
  } on ProcessException {
    throw StateError(
      'Linux needs pkexec (polkit) to start the VPN. Install polkit.',
    );
  }
  bool helperExited = false;
  unawaited(helper.exitCode.then((_) => helperExited = true));
  unawaited(helper.stdout.drain<void>());
  unawaited(helper.stderr.drain<void>());

  final String out = linuxSessionOutputs(state.path);
  // Up to two minutes: the password prompt is in front of the person.
  final DateTime deadline = DateTime.now().add(const Duration(minutes: 2));
  while (DateTime.now().isBefore(deadline)) {
    final File failure = File('$out/startup.error');
    if (await failure.exists()) {
      final String message = (await failure.readAsString()).trim();
      throw StateError(
        message.startsWith('Linux ')
            ? message
            : 'Linux could not configure the VPN tunnel.',
      );
    }
    if (await File('$out/routes-ready').exists() && await linuxTunnelUp()) {
      return;
    }
    // pkexec ended before the helper said anything: the prompt was
    // dismissed or the password refused. Nothing is running.
    if (helperExited && !await failure.exists()) {
      throw StateError('Linux VPN permission was not granted.');
    }
    await Future<void>.delayed(const Duration(milliseconds: 250));
  }
  throw StateError('Linux did not finish configuring the VPN routes.');
}

/// Asks the helper of [state] to undo everything, waits for it, and
/// removes the folder.
Future<void> stopLinuxVpnHelper(Directory state) async {
  if (!await state.exists()) {
    return;
  }
  final String out = linuxSessionOutputs(state.path);
  if (await File('$out/xray.pid').exists()) {
    await File('${state.path}/stop').create();
    for (int i = 0; i < 40; i++) {
      if (await File('$out/stopped').exists()) {
        break;
      }
      await Future<void>.delayed(const Duration(milliseconds: 250));
    }
  }
  try {
    await state.delete(recursive: true);
  } on FileSystemException {
    // Swept at the next start (see windows_temp_sweep.dart's rules).
  }
}

/// WireGuard's latest handshake as the helper of [state] last saw it: the
/// Unix epoch while there has been none, null when it has not said.
Future<DateTime?> linuxWireGuardHandshake(Directory state) async {
  try {
    final int? seconds = int.tryParse(
      (await File(
        '${linuxSessionOutputs(state.path)}/handshake',
      ).readAsString()).trim(),
    );
    return seconds == null
        ? null
        : DateTime.fromMillisecondsSinceEpoch(seconds * 1000, isUtc: true);
  } on FileSystemException {
    return null;
  }
}

/// An AppImage runs from a FUSE mount that even root may not read, so the
/// helper could not start an engine there: it goes into this session's
/// folder first, with xray's geo files.
Future<String> _copyOutOfAppImage(String engine, Directory state) async {
  final String folder = engine.substring(0, engine.lastIndexOf('/'));
  final String name = engine.substring(engine.lastIndexOf('/') + 1);
  final Directory copy = await Directory('${state.path}/runtime').create();
  for (final String file in <String>[
    name,
    if (name == 'xray') ...<String>['geoip.dat', 'geosite.dat'],
  ]) {
    await File('$folder/$file').copy('${copy.path}/$file');
  }
  await Process.run('chmod', <String>['755', '${copy.path}/$name']);
  return '${copy.path}/$name';
}

/// The start time /proc reports for [processId] (field 22), which the
/// helper compares so a reused pid does not pass for this app.
Future<String> _processStartTime(int processId) async {
  final String stat = await File('/proc/$processId/stat').readAsString();
  // Fields after the command name, which may itself contain spaces.
  final List<String> rest = stat
      .substring(stat.lastIndexOf(')') + 2)
      .split(' ');
  return rest[19];
}
