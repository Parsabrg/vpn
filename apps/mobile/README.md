# Nebula client (Android, Windows and Linux)

A Flutter 3.44 / Dart 3.12 app. It has the full account lifecycle and real
tunnels on Android and Windows. This README describes what exists today.
The repository-wide plan is `../../docs/plans/self-hosted-installation.md`.

## What exists

| Area | Android | Windows |
| --- | --- | --- |
| Account lifecycle (request, activation, sign-in, reset, sign-out) | yes | yes |
| Server and profile discovery (`GET /v1/servers/`) | yes | yes |
| WireGuard tunnel | the official `com.wireguard.android:tunnel` library (wireguard-go through JNI) in a `VpnService` (`android/app/src/main/kotlin/.../MainActivity.kt`) | the installed WireGuard for Windows client, driven through `wireguard.exe /installtunnelservice` (`lib/core/wireguard/windows_wireguard_tunnel.dart`) |
| Xray transports (VLESS over XHTTP, WebSocket, gRPC, raw TCP) | `flutter_v2ray_client` (Xray core and tun2socks in a `VpnService`) | a bundled `xray.exe` plus tun2socks supervisor (`lib/core/xray/windows_*`) |
| Hysteria2 (Salamander) | the reference Hysteria2 client, started by the patched plugin (`third_party_src/`) | a bundled `hysteria.exe` |
| Secure storage | Android Keystore through `flutter_secure_storage` | DPAPI through the vendored `third_party/flutter_secure_storage_windows` |
| Split tunnelling | per-app (VpnService disallow list) | no |
| Kill switch | not possible in-app; Settings opens Android's always-on VPN screen | no |
| Self-update check | GitHub releases (`UPDATE_REPOSITORY`) | same |

Minimum versions: Android 8.0 (API 26) and Windows 10.

### Proven, and how

These were verified by hand on real devices against one deployment (see the
status table in `../../docs/ROADMAP.md`):

- Android: WireGuard and every Xray transport carried real traffic. DNS and
  IPv6 leak protection were checked on a network that forges DNS.
- Windows: WireGuard and the Xray transports connected on a test machine,
  checked with `tool/verify_windows_tunnel.ps1`.

`flutter test` exercises Dart logic with fakes only. It does not start a
tunnel. An interface or a notification saying "connected" is not evidence of
a working tunnel either. Only traffic observed leaving through the server is.

### One build for every deployment

- **Pairing replaced the compiled-in address.** A build without
  `--dart-define=API_BASE_URL` is generic: on first launch it asks for the
  pairing link from the admin panel's *Pair a device* page (or
  `sudo nebulactl pair` on the server), checks the server against the link,
  and keeps the result in secure storage. `API_BASE_URL` still works for an
  operator's own branded build. See `lib/core/pairing/pairing.dart`.
- **Windows** finds `wireguard.exe` in Program Files or on `PATH`
  (`NEBULA_WIREGUARD_DIR` overrides). Its Xray tunnel uses the profile's
  resolvers: the deployment's, the ad-block one, or the person's own.
- "Connected" needs proof from the native side: a live engine process, and
  for WireGuard a recent handshake. When the process dies, the app turns the
  tunnel off, says so, and tries once to reconnect
  (`lib/core/tunnel/tunnel_health.dart`).

## Layout

- `lib/core/`: theming, Riverpod state, GoRouter routing, the Dio HTTP client
  with serialized token refresh, storage, and the tunnel controllers
  (`wireguard/`, `xray/`, `tunnel/`).
- `lib/features/`: one screen per user-facing flow, plus its controller.
- `android/`, `windows/`: the native runner projects.
- `third_party/`, `third_party_src/`: vendored plugin sources and the patches
  applied to them. Keep them LF (`.gitattributes`).
- `tool/`: Windows packaging and on-device verification scripts.
- `test/` mirrors `lib/`.

## Checks

```sh
flutter pub get
dart format --output=none --set-exit-if-changed .
flutter analyze --fatal-infos
flutter test
```

CI runs the same commands (`.github/workflows/flutter.yml`). A Windows build
job runs in `.github/workflows/windows.yml`.

## Building

One build serves every deployment; it is paired on first launch:

```sh
flutter build apk --release
```

Windows:

```powershell
tool/build_windows_portable.ps1
```

Linux (x64, on Linux or WSL; needs `libgtk-3-dev libsecret-1-dev
libjsoncpp-dev libayatana-appindicator3-dev desktop-file-utils`):

```sh
tool/build_linux_packages.sh   # .deb, AppImage, .tar.gz in build/packages
```

It fetches xray (SHA-256 pinned) on first run and passes its arguments to
`flutter build linux`. The .deb installs to `/opt/nebula-vpn` with the VPN
helper root-owned and a polkit action of its own, so the password prompt
names Nebula VPN; the AppImage and the portable folder run the same helper
through `/bin/bash`.

On Linux the Xray tunnel asks for the desktop's admin password (pkexec) at
connect; the root helper (`lib/core/xray/linux_vpn_supervisor.dart`) routes
everything through the `nebula` interface by firewall mark and undoes it on
disconnect, or when the app is gone. With nftables present, DNS may only
reach the tunnel's resolvers while it is up. All three transports work: Xray,
WireGuard (needs `wireguard-tools`) and Hysteria2. Sign-in is kept in the desktop keyring (GNOME Keyring or
KWallet); without one the app says so instead of starting.

An operator who wants a build that carries its own address can still pass
it, over HTTPS (the Gradle file refuses anything else):

```sh
flutter build apk --release \
  --dart-define=API_BASE_URL=https://api.example.org \
  --dart-define=API_BACKUP_URL=https://cdn.example.org   # optional
```

Do not use `--split-per-abi`: it
gives each ABI its own versionCode, and a phone that installed a split could
never update to the universal APK.

Signing uses `android/key.properties` when present. See
`../../docs/runbooks/release-signing-key.md`.

For local development against the Compose stack, a debug build defaults to
`http://10.0.2.2:8000` (the Android emulator's alias for the host).
