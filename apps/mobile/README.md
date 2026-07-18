# Nebula mobile client

This directory is the Flutter 3.44 / Dart 3.12 workspace for the Android and
Windows client. Phase 1.1 intentionally contains only the tested shared
application shell. Authentication, credential storage, tunnel control, and VPN
connectivity belong to later milestones.

Android and Windows runner projects are deferred until the owner confirms the
minimum supported OS versions. This avoids committing generated platform settings
that imply an unsupported compatibility promise.

## Checks

```sh
flutter pub get
dart format --output=none --set-exit-if-changed .
flutter analyze
flutter test
```
