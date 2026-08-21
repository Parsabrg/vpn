# Nebula mobile client

This directory is the Flutter 3.44 / Dart 3.12 workspace for the Android and
Windows client. Phase 1.7a replaced the Phase 1.1 placeholder shell with a
themed, routed, stateful app covering the account lifecycle end to end:
account requests, activation, sign-in, password reset, and an authenticated
home shell with account and settings screens, all wired to the real API.

Device connection (WireGuard) is still an honest empty state -- the API has
no public endpoint yet for a user to discover which server/profile they're
allowed to use, so that screen names the Phase 1.7b dependency instead of
faking a device list. See `docs/phase-1-plan.md` and `PROJECT_PROGRESS.md`
at the repository root for the exact status.

Android and Windows runner projects are still deferred until the owner
confirms the minimum supported OS versions. This phase stays Dart-only and
fully exercised by `flutter test` -- no device or emulator is needed.

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
