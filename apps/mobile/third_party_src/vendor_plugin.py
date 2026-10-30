"""Rebuilds the patched flutter_v2ray_client that the app builds against.

Run before the first build, and after any `flutter pub get` that changes the
plugin version:

    python third_party_src/vendor_plugin.py

Why the plugin is patched at all: Hysteria2 does not run on Xray-core. Xray
accepts Salamander obfuscation and silently discards it -- a client offering a
deliberately wrong password authenticates -- so a server configured for
obfuscation has none, and a client applying real Salamander cannot reach one
that does. The patch runs the reference Hysteria2 client as a child process
behind the tun2socks bridge instead. See docs/adr/0003 and 0004.

Why vendored rather than forked: the upstream plugin is unmodified apart from
the patch here, and a fork would mean carrying a 53MB `.aar` in this
repository to change a few hundred lines.

Why the binaries are fetched rather than committed: four ABIs at ~22MB each is
90MB of release artifacts that are already published, immutable, and pinned by
digest below. Anything that does not match its digest is refused.
"""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

PLUGIN = "flutter_v2ray_client"
VERSION = "3.4.1"
HYSTERIA_RELEASE = "app%2Fv2.12.2"

# sha256 of each official release asset, verified against what this app was
# built and tested with. A mismatch means the artifact is not the one this
# patch was written against -- refuse rather than ship an unknown binary.
BINARIES = {
    "arm64-v8a": (
        "hysteria-android-arm64",
        "50a0e3301edd5ad63ec2c9915716b9b4ae93de369813f045e1e6ab8d85057319",
    ),
    "armeabi-v7a": (
        "hysteria-android-armv7",
        "5c7c25746cfb765e49ad551e0555b3e804295081e4dd7e06255517d03dc4a2d1",
    ),
    "x86_64": (
        "hysteria-android-amd64",
        "c56f78a73601f77a7f16550eaf25dc396c8e43f9cb8a6e7e6eb6a7a6aefdcab1",
    ),
    "x86": (
        "hysteria-android-386",
        "63dd3c8e4bd7e8cd542d17f20b7178240e956ace3d3839e4072dd03a34af6c47",
    ),
}

# The Xray engine itself. The plugin ships one (26.6.1 with 3.4.1); this is
# the release the desktop runtimes pin, for its newer TLS options (the fragment
# lists, Encrypted Client Hello lookups), from 2dust's AndroidLibXrayLite.
XRAY_AAR = (
    "https://github.com/2dust/AndroidLibXrayLite/releases/download/v26.9.30/libv2ray.aar",
    "cf71680b776b9ca583747ba652f816b047a655eab875d8951e6141636d88bbd6",
)

# hev-socks5-tunnel, the bridge from the VPN interface to the engine's local
# proxy, in place of the badvpn tun2socks the plugin ships: after hours of use
# that one left the tunnel reading "connected" while carrying nothing, and
# v2rayNG had already moved to hev. There is no released Android library, and
# the JNI class name is compiled in, so it is built here from a pinned commit
# (its submodules are pinned by that commit) with the Android NDK.
HEV_REPO = "https://github.com/heiher/hev-socks5-tunnel"
HEV_TAG = "2.18.0"
HEV_COMMIT = "d9dca26c7ad0e494492244f0309e80ee583e739e"
HEV_JNI_CLASS = ("dev/amirzr/flutter_v2ray_client/v2ray/services", "TProxyService")

HERE = Path(__file__).resolve().parent
MOBILE = HERE.parent
TARGET = MOBILE / "third_party" / PLUGIN
PATCH = HERE / f"{PLUGIN}-{VERSION}.patch"


def pub_cache_source() -> Path:
    for root in (
        Path.home() / "AppData" / "Local" / "Pub" / "Cache",
        Path.home() / ".pub-cache",
    ):
        candidate = root / "hosted" / "pub.dev" / f"{PLUGIN}-{VERSION}"
        if candidate.is_dir():
            return candidate
    raise SystemExit(
        f"{PLUGIN}-{VERSION} not in the pub cache. Run `flutter pub get` first."
    )


def fetch(abi: str, asset: str, digest: str, into: Path) -> None:
    into.mkdir(parents=True, exist_ok=True)
    destination = into / "libhysteria.so"
    if destination.exists():
        if hashlib.sha256(destination.read_bytes()).hexdigest() == digest:
            print(f"  {abi:<12} already present")
            return
        destination.unlink()

    url = (
        "https://github.com/apernet/hysteria/releases/download/"
        f"{HYSTERIA_RELEASE}/{asset}"
    )
    print(f"  {abi:<12} downloading {asset}")
    with urllib.request.urlopen(url, timeout=300) as response:  # noqa: S310
        payload = response.read()
    actual = hashlib.sha256(payload).hexdigest()
    if actual != digest:
        raise SystemExit(
            f"{asset} digest mismatch\n  expected {digest}\n  got      {actual}"
        )
    destination.write_bytes(payload)


def fetch_engine(into: Path) -> None:
    url, digest = XRAY_AAR
    print(f"  downloading {url.rsplit('/', 3)[-2]} libv2ray.aar")
    with urllib.request.urlopen(url, timeout=600) as response:  # noqa: S310
        payload = response.read()
    actual = hashlib.sha256(payload).hexdigest()
    if actual != digest:
        raise SystemExit(
            f"libv2ray.aar digest mismatch\n  expected {digest}\n  got      {actual}"
        )
    into.write_bytes(payload)


def android_ndk() -> Path:
    """The NDK: ANDROID_NDK_HOME, else the newest under the Android SDK."""
    if os.environ.get("ANDROID_NDK_HOME"):
        return Path(os.environ["ANDROID_NDK_HOME"])
    sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    properties = MOBILE / "android" / "local.properties"
    if not sdk and properties.is_file():
        for line in properties.read_text(encoding="utf-8").splitlines():
            if line.startswith("sdk.dir="):
                # A properties file escapes ':' and '\'.
                sdk = line.split("=", 1)[1].replace(r"\:", ":").replace("\\\\", "\\")
    root = Path(sdk) / "ndk" if sdk else None
    versions = sorted(
        (path for path in root.iterdir() if path.is_dir()),
        key=lambda path: [int(part) for part in path.name.split(".") if part.isdigit()],
    ) if root and root.is_dir() else []
    if not versions:
        raise SystemExit("Android NDK not found: install one with the SDK manager or set ANDROID_NDK_HOME.")
    return versions[-1]


def build_hev(jni_libs: Path) -> None:
    ndk_build = android_ndk() / ("ndk-build.cmd" if os.name == "nt" else "ndk-build")
    package, cls = HEV_JNI_CLASS
    with tempfile.TemporaryDirectory() as work:
        source = Path(work) / "hev"
        subprocess.run(
            ["git", "-c", "advice.detachedHead=false", "clone", "--quiet", "--depth", "1", "--branch", HEV_TAG,
             "--recursive", "--shallow-submodules", HEV_REPO, str(source)],
            check=True,
        )
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=source, check=True,
            capture_output=True, text=True,
        ).stdout.strip()
        if head != HEV_COMMIT:
            raise SystemExit(f"hev-socks5-tunnel {HEV_TAG} is {head}, expected {HEV_COMMIT}")
        subprocess.run(
            [str(ndk_build), "NDK_PROJECT_PATH=.", "APP_BUILD_SCRIPT=Android.mk",
             "NDK_APPLICATION_MK=Application.mk", "APP_PLATFORM=android-26",
             f"APP_CFLAGS=-O3 -DPKGNAME={package} -DCLSNAME={cls}", "-j8"],
            cwd=source, check=True, capture_output=True,
        )
        for abi in BINARIES:
            built = source / "libs" / abi / "libhev-socks5-tunnel.so"
            shutil.copyfile(built, jni_libs / abi / "libhev-socks5-tunnel.so")
            # badvpn's tun2socks, which hev replaces.
            (jni_libs / abi / "libtun2socks.so").unlink(missing_ok=True)
            print(f"  {abi:<12} built")


def main() -> None:
    source = pub_cache_source()
    print(f"vendoring {source.name}")
    if TARGET.exists():
        shutil.rmtree(TARGET, ignore_errors=True)
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, TARGET)
    # The pub cache is read-only; the copy has to be writable to patch.
    for path in TARGET.rglob("*"):
        if path.is_file():
            path.chmod(0o644)

    print("applying patch")
    # GIT_CEILING_DIRECTORIES stops git discovering this repository around
    # the copy. Inside a work tree, `git apply` resolves the patch's paths
    # against the repository root, finds none of them, reports each as
    # "Skipped patch" and exits 0 -- leaving an unpatched plugin that builds
    # fine and whose Hysteria2 profile carries nothing.
    environment = {**os.environ, "GIT_CEILING_DIRECTORIES": str(TARGET.parent.parent)}
    result = subprocess.run(
        ["git", "apply", "--verbose", "--unsafe-paths", f"--directory={TARGET.name}", str(PATCH)],
        cwd=TARGET.parent,
        capture_output=True,
        text=True,
        env=environment,
    )
    if result.returncode != 0 or "Skipped patch" in result.stderr:
        raise SystemExit(f"patch failed:\n{result.stderr}")

    print("fetching Hysteria2 binaries (pinned by digest)")
    for abi, (asset, digest) in BINARIES.items():
        fetch(abi, asset, digest, TARGET / "android/src/main/jniLibs" / abi)

    print(f"building hev-socks5-tunnel {HEV_TAG} (pinned by commit)")
    build_hev(TARGET / "android/src/main/jniLibs")

    print("fetching the Xray engine (pinned by digest)")
    fetch_engine(TARGET / "android/libs/libv2ray.aar")

    print()
    print("done. `flutter build apk` will now use the patched plugin via")
    print("pubspec_overrides.yaml.")


if __name__ == "__main__":
    sys.exit(main())
