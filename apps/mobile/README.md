# Nebula mobile client

This directory is the Flutter 3.44 / Dart 3.12 workspace for the Android and
Windows client. Phase 1.7a replaced the Phase 1.1 placeholder shell with a
themed, routed, stateful app covering the account lifecycle end to end:
account requests, activation, sign-in, password reset, and an authenticated
home shell with account and settings screens, all wired to the real API.

Phase 1.7b adds device connection: the devices screen calls the API's
`GET /v1/servers/` to list the server/profiles the signed-in user is
permitted to use, generates a Curve25519 WireGuard identity on-device
(`package:cryptography`'s pure-Dart X25519 -- no native code needed), and
calls `POST /v1/devices/{id}/wireguard-peer` (and its `/revoke` counterpart)
to provision or release a peer. Provisioning a peer registers the device
with the server; it does not establish a live tunnel yet, and the screen
says so explicitly -- that needs native Android/Windows platform
integration this app doesn't have (see below).

Android and Windows runner projects are still deferred until the owner
confirms the minimum supported OS versions. This app stays Dart-only and
fully exercised by `flutter test` -- no device or emulator is needed. See
`docs/phase-1-plan.md` and `PROJECT_PROGRESS.md` at the repository root for
the exact status.

## Layout

- `lib/core/` -- theming, Riverpod state, GoRouter routing, the Dio HTTP
  client (with token-refresh serialization), and secure/local storage.
  Cross-cutting, not screen-specific.
- `lib/features/` -- one screen (plus a controller where it has submission
  state distinct from `AuthNotifier`) per user-facing flow.
- `test/` mirrors `lib/`.

## Checks

```sh
flutter pub get
dart format --output=none --set-exit-if-changed .
flutter analyze --fatal-infos
flutter test
```

## Configuration

`API_BASE_URL` is injected at build/test time via `--dart-define`, defaulting
to `http://10.0.2.2:8000` (the Android emulator's alias for the host
machine's `localhost`, matching this repo's `compose.yaml`). Override for a
real device or a non-local API:

```sh
flutter run --dart-define=API_BASE_URL=https://your-api-host
```
