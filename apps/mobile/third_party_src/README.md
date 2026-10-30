# Patched `flutter_v2ray_client`

The app builds against a patched copy of this plugin. Regenerate it before the
first build, and after any `flutter pub get` that changes the plugin version:

```
python third_party_src/vendor_plugin.py
```

The result lands in `../third_party/` and is gitignored: it is ~145MB of
upstream code and release binaries, all of it reproducible from the patch and
the digests pinned in the script.

`flutter pub get` will fail until you run it, because `pubspec_overrides.yaml`
points at a directory that does not exist yet. That is deliberate -- failing is
better than quietly building an app whose Hysteria2 profile connects and
carries nothing, which is exactly what shipped before this patch existed.

## The Xray engine

The plugin ships Xray 26.6.1 in `android/libs/libv2ray.aar`. The script
replaces it with 2dust's AndroidLibXrayLite v26.9.30, pinned by digest -- the
release the desktop runtimes use. Its Java interface changed: no socket
protector (none is needed, the app is outside its own VPN), and one call for
every outbound's counters (`queryAllOutboundTrafficStats`) instead of one per
tag; the patch follows both.

## What the patch changes

Nine files, ~450 lines. Most of it is the Hysteria2 path; the rest is the
notification.

**Hysteria2 runs as a child process, not on Xray-core.** Xray accepts
Salamander obfuscation and silently discards it: a client offering a
deliberately wrong password authenticates successfully, so a server configured
for obfuscation has none, and a client applying real Salamander cannot reach
one that does. Measured against the live server; see `docs/adr/0003`. When the
config carries `nebulaHysteriaConfig`, the plugin writes that YAML and runs the
reference `hysteria` binary from `jniLibs`, exposing SOCKS5 on the port
tun2socks already dials. Xray is not started.

**The delay test runs in the daemon process, never in the app's.**
`getServerDelay` hands the config to `DelayProbeService`
(`:RunSoLibV2RayDaemon`, beside the tunnel's own Xray) and waits for the
answer through a `ResultReceiver`. Run in the app's process, it loaded Xray's
Go runtime there; WireGuard's Go backend then loaded a second one into the
same process, and the app died with SIGSEGV as soon as WireGuard came up.
Seen on a phone: test the protocols, then connect with WireGuard.

**The delay test runs Hysteria2 the same way.** `getServerDelay` with a
config carrying `nebulaHysteriaConfig` starts the reference client for the
length of the test, on the port given in `nebulaHysteriaPort`, and has Xray
measure through it with a `socks` outbound. The client is stopped and its
YAML deleted afterwards. Measured by Xray alone, the test would report on a
connection without Salamander, which is not the one a connect makes.

**The tunnel is brought up explicitly on that path.** `setup()` -- which calls
`establish()` and starts tun2socks -- normally runs from Xray-core's own
`startup()` callback, which only fires inside `startLoop()`. Without this the
service reports connected with no interface at all and traffic leaves
untouched. It runs off the main thread and only once the child is accepting,
because Android destroys a service that has not gone foreground within a few
seconds, and tun2socks dials that port the moment it starts.

**"Connected" is reported only once `setup()` has actually run**, not the
moment the Hysteria2 process is spawned. The two used to be conflated: the
service went foreground and told Flutter CONNECTED in the same breath,
before the background bring-up thread had confirmed the child's local port
and called `setup()` at all. Flutter's status listener treats CONNECTED as
"resolve the pending connect() call" (see
`AndroidXrayTunnelController._handleStatusChanged` in the app), so the app
reported Protected while `tun0` did not exist yet -- every packet left over
the underlying network, unencrypted, for however long the bring-up thread's
`waitForLocalPort` took, which is bounded at ten seconds and grows on a
network already interfering with the connection. Reported from the field as
"connects, then works a few seconds later." Going foreground still happens
immediately (Android's deadline for that is real and unrelated to whether
the tunnel works yet); only the state flag moved.

**Tapping the notification opens the app; only its button disconnects.**
Upstream built one `PendingIntent` carrying the `FROM_DISCONNECT_BTN` action
and passed the same one to both `setContentIntent` (the notification body)
and `addAction` (the Disconnect button). `MainActivity` reads that action as
"the user pressed Disconnect" and hands it to Dart, so every tap anywhere on
the notification tore the tunnel down -- reported from the field as "clicking
the notification disconnects it, it should just open the app". The patch
gives the body a plain launch intent and keeps the action for the button
only, on its own request code (two `PendingIntent`s the system considers
equal share one registration, and `FLAG_UPDATE_CURRENT` would then have the
second overwrite the first). The `stopIntent`/`pendingIntent` pair a few
lines below is upstream's, is unused, and is left alone: this app disconnects
through its own state machine so the server-side credential is revoked too,
which stopping the service on its own would skip.

**The app is excluded from its own tunnel** (`addDisallowedApplication`). A
child process's sockets cannot be reached by `VpnService.protect()` from this
process, so package exclusion is the only mechanism that keeps its traffic out
of the interface it is feeding. v2rayNG does the same.

**The notification shows the live speed.** Upstream posts it once, with a
title and nothing else. The patch updates its text every second with the
download and upload speed the core already measures for the app's own counters,
and `startV2Ray` takes `notificationShowSpeed` so the app's setting can turn it
off. The flag travels in `V2rayConfig` because the service runs in its own
process, where `AppConfigs` statics set by the plugin are not visible. On the
Hysteria2 path there is no Xray core to ask, so the kernel's per-app byte
counters stand in.

**tun2socks relays UDP with `--socks5-udp`, not `--enable-udprelay`.** The
local SOCKS proxy requires a username and password, which tun2socks is given.
Its standard SOCKS5 UDP relay logs in the same way the TCP side does; the older
`--enable-udprelay` relay does not, so every UDP packet was dropped. DNS still
appeared to work because Android fell back to DNS over TLS on TCP, which is
what made pages fail for 8 to 20 seconds after every connect. QUIC and voice
calls had no fallback.

## Regenerating the patch

Edit the vendored copy in `../third_party/`, then diff it against the pub
cache copy and check the result applies to a fresh copy before committing. A
patch that does not reproduce the vendored files exactly is a build that
differs from the one that was tested.

## Why not a fork

The plugin is unmodified apart from this patch, and a fork would mean carrying
its 53MB `.aar` in this repository to change a few hundred lines. If the patch
starts failing to apply against new upstream releases, revisit that.
