# Third-party software in Nebula VPN

Nebula VPN is licensed under the GNU General Public License, version 3 or any
later version (`GPL-3.0-or-later`, see [LICENSE](LICENSE)). It ships, or
builds against, the software below. Each keeps its own license; every one is
compatible with distributing Nebula under the GPL. This file is the license
audit for the public-release checklist (docs/roadmap-sections.md, section 101).
Re-check it when a dependency or a bundled binary changes.

Audited 2026-10-17 against `apps/mobile/pubspec.lock`, the three services'
locked environments, `apps/admin/package-lock.json` (production packages)
and the vendoring scripts that fetch the engines.

## Bundled engines and native libraries

These ship as separate programs or libraries beside the app. Where one is not
linked into Nebula's own code, the GPL treats the combination as an
aggregate and each keeps its own terms.

| Component | Where | License | Notes |
|---|---|---|---|
| Xray-core | Windows, Linux (`xray`) | MPL-2.0 | XTLS/Xray-core. MPL-2.0 is compatible with GPL-3.0. |
| AndroidLibXrayLite (`libv2ray.aar`, `libgojni.so`) | Android | LGPL-3.0 | 2dust/AndroidLibXrayLite; Xray-core underneath. |
| Hysteria | all (`hysteria`, `libhysteria.so`) | MIT | apernet/hysteria |
| hev-socks5-tunnel (`libhev-socks5-tunnel.so`) | Android | MIT | heiher/hev-socks5-tunnel, built from source by `vendor_plugin.py` |
| WireGuard for Android (`libwg-go.so`, `libwg.so`, `libwg-quick.so`) | Android | Apache-2.0 (tunnel library), MIT (wireguard-go) | WireGuard/wireguard-android |
| Wintun (`wintun.dll`) | Windows | WireGuard LLC "Prebuilt Binaries License" | Redistributed unmodified, as that license allows; loaded by Xray, not linked into Nebula. Its terms ship beside it as `LICENSE-wintun.txt`. |
| GeoIP database (`geoip.dat`) | Windows, Linux | CC-BY-SA-4.0 | v2fly/geoip, via the Xray release. Attribution: v2fly contributors. CC-BY-SA-4.0 is one-way compatible with GPL-3.0. |
| Domain lists (`geosite.dat`) | Windows, Linux | MIT | v2fly/domain-list-community, via the Xray release. |
| CameraX (`libimage_processing_util_jni.so`, `libsurface_util_jni.so`) | Android | Apache-2.0 | AndroidX camera libraries, used by the QR scanner. |
| Flutter engine and Dart runtime | all | BSD-3-Clause | |

## The app's Dart packages

105 packages from `pubspec.lock` (direct and transitive), read from each
package's LICENSE file:

| License | Packages |
|---|---|
| BSD-3-Clause | 84 (including the Flutter SDK packages, `camera`, `zxing2`, `flutter_secure_storage`, `go_router`, `intl`, `shared_preferences`) |
| MIT | 15 (including `dio`, `flutter_riverpod`, `tray_manager`, `window_manager`) |
| Apache-2.0 | 4 (including `cryptography`) |

Two are vendored and patched in this repository:
`flutter_v2ray_client` (MIT, Amir Ziari) and `flutter_secure_storage_windows`
(BSD-3-Clause, German Saprykin). Their license files are kept with them.

**Removed for this audit:** `mobile_scanner`. Its Android build bundled
Google's closed ML Kit barcode library, with parts of Play Services and
Firebase -- not compatible with shipping Nebula under the GPL, and not a fit
for a privacy tool. The QR scanner now decodes with ZXing (`zxing2`,
BSD-3-Clause) from `camera` frames, and the app no longer carries any Google
proprietary component.

## Server side

| Part | Packages | Licenses |
|---|---|---|
| API, agent, worker (Python) | 81 | MIT, BSD, Apache-2.0, ISC, PSF and MPL-2.0; `psycopg` and `psycopg-binary` are LGPL-3.0-only |
| Admin panel (npm, production) | 53 | MIT, Apache-2.0, ISC, BSD-3-Clause, 0BSD; `sharp`'s `libvips` binaries are LGPL-3.0-or-later; `caniuse-lite` data is CC-BY-4.0 |
| AdGuard Home (self-hosted resolver image) | 1 | GPL-3.0 |

LGPL-3.0 and CC-BY-4.0 are compatible with GPL-3.0; CC-BY-4.0 needs the
attribution kept, which `caniuse-lite` carries in its own package.

## Where a person finds this in the app

The app's licenses page (Settings › Open-source licenses) lists every Dart
package's license, collected by Flutter at build time, and the bundled
engines above.
