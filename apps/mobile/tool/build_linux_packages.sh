#!/usr/bin/env bash
# Builds the Linux release and packages it, x64:
#   nebula-vpn_<version>_amd64.deb   installs to /opt/nebula-vpn, with the VPN
#                                    helper root-owned and a polkit action of
#                                    its own, so the password prompt names
#                                    Nebula VPN
#   nebula-vpn-<version>-linux-x64.tar.gz   portable folder; its helper runs
#                                    through /bin/bash instead
#   Nebula_VPN-<version>-x86_64.AppImage    one portable file, the same way
# Arguments go to `flutter build linux` (e.g. --dart-define=...). The output
# folder is OUTPUT_DIRECTORY, by default build/packages. The AppImage tools
# are fetched once into build/appimage-tools, SHA-256 pinned (pinned on
# first download, 2026-10-01: their releases publish no digests).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
version="$(sed -n 's/^version: \([0-9.]*\).*/\1/p' pubspec.yaml)"
out="${OUTPUT_DIRECTORY:-$root/build/packages}"
mkdir -p "$out"

[ -x assets/linux_runtime/xray ] || tool/vendor_linux_runtime.sh
flutter build linux --release "$@"
bundle="$root/build/linux/x64/release/bundle"

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
pkg="$stage/nebula-vpn"
mkdir -p "$pkg/DEBIAN" "$pkg/opt/nebula-vpn" "$pkg/usr/bin" \
  "$pkg/usr/lib/nebula-vpn" "$pkg/usr/share/applications" \
  "$pkg/usr/share/icons/hicolor/256x256/apps" "$pkg/usr/share/polkit-1/actions"
cp -a "$bundle/." "$pkg/opt/nebula-vpn/"
chmod 755 "$pkg/opt/nebula-vpn/data/flutter_assets/assets/linux_runtime/xray" \
  "$pkg/opt/nebula-vpn/data/flutter_assets/assets/linux_runtime/hysteria"
ln -s /opt/nebula-vpn/nebulavpn "$pkg/usr/bin/nebulavpn"

# The helper is the very script the app carries, taken from its source --
# without the CRs of a Windows checkout, which Dart drops from the string
# but bash would not.
helper="$pkg/usr/lib/nebula-vpn/nebula-vpn-helper"
sed -n "/^const String linuxVpnSupervisorScript = r'''/,/^''';/p" \
  lib/core/xray/linux_vpn_supervisor.dart | sed "1s/^.*r'''//;\$d" | tr -d '\r' > "$helper"
chmod 755 "$helper"
bash -n "$helper"
head -1 "$helper" | grep -qx '#!/bin/bash'

# The icon: the 256 px frame of the Windows icon, which is a PNG already.
python3 - assets/app_icon.ico \
  "$pkg/usr/share/icons/hicolor/256x256/apps/nebula-vpn.png" <<'PY'
import struct, sys
data = open(sys.argv[1], 'rb').read()
count = struct.unpack('<HHH', data[:6])[2]
frames = [struct.unpack('<BBBBHHII', data[6 + 16 * i:22 + 16 * i]) for i in range(count)]
_, _, _, _, _, _, size, offset = max(frames, key=lambda f: f[0] or 256)
open(sys.argv[2], 'wb').write(data[offset:offset + size])
PY

cat > "$pkg/usr/share/applications/org.nebulavpn.nebula_mobile.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=Nebula VPN
Comment=Connect this computer to your Nebula VPN
Exec=nebulavpn
Icon=nebula-vpn
Terminal=false
Categories=Network;
StartupWMClass=nebulavpn
EOF

cat > "$pkg/usr/share/polkit-1/actions/org.nebulavpn.tunnel.policy" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC
 "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <vendor>Nebula VPN</vendor>
  <action id="org.nebulavpn.tunnel">
    <description>Connect Nebula VPN</description>
    <message>Nebula VPN needs permission to send this computer's traffic through the VPN.</message>
    <icon_name>nebula-vpn</icon_name>
    <defaults>
      <allow_any>auth_admin</allow_any>
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>auth_admin_keep</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.exec.path">/usr/lib/nebula-vpn/nebula-vpn-helper</annotate>
  </action>
</policyconfig>
EOF

cat > "$pkg/DEBIAN/control" <<EOF
Package: nebula-vpn
Version: $version
Architecture: amd64
Section: net
Priority: optional
Maintainer: Nebula VPN <146811678+Parsabrg@users.noreply.github.com>
Installed-Size: $(du -sk "$pkg" | cut -f1)
Depends: libgtk-3-0t64 | libgtk-3-0, libsecret-1-0, libayatana-appindicator3-1, pkexec | policykit-1, iproute2
Recommends: gnome-keyring | kwalletmanager, wireguard-tools, nftables
Description: Nebula VPN client
 Connects this computer to a Nebula VPN deployment, sending all of its
 traffic and DNS through the tunnel.
EOF

dpkg-deb --root-owner-group --build "$pkg" "$out/nebula-vpn_${version}_amd64.deb" >/dev/null
tar -C "$(dirname "$bundle")" -czf "$out/nebula-vpn-$version-linux-x64.tar.gz" \
  --transform "s,^bundle,nebula-vpn-$version," bundle

# --- AppImage -------------------------------------------------------------
tools="$root/build/appimage-tools"
mkdir -p "$tools"
fetch_tool() { # url, file, expected sha256
  if [ ! -f "$tools/$2" ] || [ "$(sha256sum "$tools/$2" | cut -d' ' -f1)" != "$3" ]; then
    curl -fsSL --retry 3 -o "$tools/$2" "$1"
  fi
  if [ "$(sha256sum "$tools/$2" | cut -d' ' -f1)" != "$3" ]; then
    echo "SHA-256 mismatch for $2" >&2
    exit 1
  fi
  chmod 755 "$tools/$2"
}
fetch_tool https://github.com/AppImage/appimagetool/releases/download/1.9.0/appimagetool-x86_64.AppImage \
  appimagetool 46fdd785094c7f6e545b61afcfb0f3d98d8eab243f644b4b17698c01d06083d1
fetch_tool https://github.com/AppImage/type2-runtime/releases/download/20251108/runtime-x86_64 \
  runtime 2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d

appdir="$stage/Nebula_VPN.AppDir"
mkdir -p "$appdir"
cp -a "$bundle/." "$appdir/"
chmod 755 "$appdir/data/flutter_assets/assets/linux_runtime/xray" \
  "$appdir/data/flutter_assets/assets/linux_runtime/hysteria"
cat > "$appdir/AppRun" <<'EOF'
#!/bin/sh
exec "$(dirname "$(readlink -f "$0")")/nebulavpn" "$@"
EOF
chmod 755 "$appdir/AppRun"
cp "$pkg/usr/share/applications/org.nebulavpn.nebula_mobile.desktop" "$appdir/"
cp "$pkg/usr/share/icons/hicolor/256x256/apps/nebula-vpn.png" "$appdir/nebula-vpn.png"
ln -s nebula-vpn.png "$appdir/.DirIcon"
# Extract-and-run: building needs no FUSE.
ARCH=x86_64 APPIMAGE_EXTRACT_AND_RUN=1 "$tools/appimagetool" --no-appstream \
  --runtime-file "$tools/runtime" "$appdir" "$out/Nebula_VPN-$version-x86_64.AppImage" >/dev/null
ls -la "$out"
