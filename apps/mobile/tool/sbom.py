"""A CycloneDX SBOM for a Nebula release, read from the pins already in the repo.

    python apps/mobile/tool/sbom.py --version 0.1.22 > nebula-vpn-v0.1.22-sbom.cdx.json

Nothing here is a second list of versions to keep in step: every entry is read
from the file that actually pins it -- pubspec.lock for the app's Dart
packages, the vendoring scripts for the engines shipped beside it (each with
the digest the build refuses to run without), the Gradle file for Android's
WireGuard library, and pyproject.toml / package-lock.json for the server.
Uploaded with each release beside SHA256SUMS.txt (roadmap section 68).

Not covered: Windows uses the WireGuard installed on the machine rather than
one it ships, and Flutter's own engine is recorded as the SDK version only.
pubspec.lock does not say which transitive packages only the dev tools use,
so a few listed may not ship; over-listing is the safe direction to be wrong.
"""

import argparse
import importlib.util
import json
import re
import sys
import tomllib
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
MOBILE = ROOT / "apps" / "mobile"


def _component(
    kind: str,
    name: str,
    version: str,
    purl: str,
    group: str,
    sha256: str | None = None,
    url: str | None = None,
) -> dict[str, Any]:
    component: dict[str, Any] = {
        "type": kind,
        "name": name,
        "version": version,
        "purl": purl,
        "properties": [{"name": "nebula:part", "value": group}],
    }
    if sha256:
        component["hashes"] = [{"alg": "SHA-256", "content": sha256.lower()}]
    if url:
        component["externalReferences"] = [{"type": "distribution", "url": url}]
    return component


def dart_packages() -> list[dict[str, Any]]:
    """Shipped Dart packages: everything in pubspec.lock but dev-only ones."""

    text = (MOBILE / "pubspec.lock").read_text(encoding="utf-8")
    components = []
    for block in re.split(r"\n  (?=[a-z0-9_]+:\n)", text.split("packages:\n", 1)[1]):
        name = block.split(":", 1)[0].strip()
        dependency = re.search(r'dependency: "?([^"\n]+)"?', block)
        version = re.search(r'version: "([^"]+)"', block)
        if not name or not version or (dependency and "dev" in dependency.group(1)):
            continue
        if "source: path" in block:
            # The vendored, patched plugin: listed with the Android engines,
            # where its patch is recorded.
            continue
        digest = re.search(r'sha256: "?([0-9a-f]{64})"?', block)
        components.append(
            _component(
                "library",
                name,
                version.group(1),
                f"pkg:pub/{name}@{version.group(1)}",
                "app",
                digest.group(1) if digest else None,
            )
        )
    return components


def android_engines() -> list[dict[str, Any]]:
    spec = importlib.util.spec_from_file_location(
        "vendor_plugin", MOBILE / "third_party_src" / "vendor_plugin.py"
    )
    assert spec and spec.loader
    plugin = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(plugin)
    hysteria = plugin.HYSTERIA_RELEASE.replace("app%2F", "")
    components = [
        _component(
            "library",
            plugin.PLUGIN,
            f"{plugin.VERSION}+nebula-patch",
            f"pkg:pub/{plugin.PLUGIN}@{plugin.VERSION}",
            "app-android",
        )
    ]
    aar_url, aar_hash = plugin.XRAY_AAR
    aar_version = aar_url.split("/download/")[1].split("/")[0]
    components.append(
        _component(
            "library",
            "AndroidLibXrayLite",
            aar_version,
            f"pkg:github/2dust/AndroidLibXrayLite@{aar_version}",
            "app-android",
            aar_hash,
            aar_url,
        )
    )
    for abi, (asset, digest) in plugin.BINARIES.items():
        components.append(
            _component(
                "application",
                f"hysteria ({abi})",
                hysteria,
                f"pkg:github/apernet/hysteria@app/{hysteria}?arch={abi}",
                "app-android",
                digest,
                f"https://github.com/apernet/hysteria/releases/download/app/{hysteria}/{asset}",
            )
        )
    gradle = (MOBILE / "android" / "app" / "build.gradle.kts").read_text(encoding="utf-8")
    wireguard = re.search(r'"com\.wireguard\.android:tunnel:([^"]+)"', gradle)
    if wireguard:
        components.append(
            _component(
                "library",
                "wireguard-android tunnel",
                wireguard.group(1),
                f"pkg:maven/com.wireguard.android/tunnel@{wireguard.group(1)}",
                "app-android",
            )
        )
    return components


def desktop_engines() -> list[dict[str, Any]]:
    components = []
    linux = (MOBILE / "tool" / "vendor_linux_runtime.sh").read_text(encoding="utf-8")
    pins = dict(re.findall(r"^(\w+)='([^']+)'$", linux, re.MULTILINE))
    for engine, owner in (("xray", "XTLS/Xray-core"), ("hysteria", "apernet/hysteria")):
        components.append(
            _component(
                "application",
                f"{engine} (linux-amd64)",
                pins[f"{engine}_version"],
                f"pkg:github/{owner}@{pins[f'{engine}_version']}?arch=linux-amd64",
                "app-linux",
                pins[f"{engine}_hash"],
            )
        )
    windows = (MOBILE / "tool" / "vendor_windows_runtime.ps1").read_text(encoding="utf-8")
    values = dict(re.findall(r"^\$(\w+) = '([^']+)'$", windows, re.MULTILINE))
    hysteria = re.search(r"hysteria/releases/download/app/(v[^/]+)/", windows)
    components.append(
        _component(
            "application",
            "xray (windows-amd64, archive)",
            values["xrayVersion"],
            f"pkg:github/XTLS/Xray-core@{values['xrayVersion']}?arch=windows-64",
            "app-windows",
            values["xrayHash"],
        )
    )
    if hysteria:
        components.append(
            _component(
                "application",
                "hysteria (windows-amd64)",
                hysteria.group(1),
                f"pkg:github/apernet/hysteria@app/{hysteria.group(1)}?arch=windows-amd64",
                "app-windows",
                values["hysteriaHash"],
            )
        )
    return components


def python_packages() -> list[dict[str, Any]]:
    components = []
    for service in ("api", "worker", "vpn-agent"):
        project = tomllib.loads((ROOT / "services" / service / "pyproject.toml").read_text())
        for requirement in project["project"]["dependencies"]:
            match = re.match(r"([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?==([^;\s]+)", requirement)
            if match:
                name, version = match.groups()
                components.append(
                    _component(
                        "library",
                        name,
                        version,
                        f"pkg:pypi/{name.lower()}@{version}",
                        f"server-{service}",
                    )
                )
    return components


def npm_packages() -> list[dict[str, Any]]:
    lock = json.loads((ROOT / "apps" / "admin" / "package-lock.json").read_text(encoding="utf-8"))
    components = []
    for path, package in lock.get("packages", {}).items():
        if not path or package.get("dev") or "version" not in package:
            continue
        name = path.split("node_modules/")[-1]
        components.append(
            _component(
                "library",
                name,
                package["version"],
                f"pkg:npm/{name.replace('@', '%40')}@{package['version']}",
                "server-admin",
            )
        )
    return components


def build(version: str) -> dict[str, Any]:
    pubspec = (MOBILE / "pubspec.yaml").read_text(encoding="utf-8")
    flutter = re.search(r'flutter: ">=?\s*([0-9.]+)', pubspec)
    components = (
        dart_packages() + android_engines() + desktop_engines() + python_packages() + npm_packages()
    )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": {"type": "application", "name": "nebula-vpn", "version": version},
            "properties": [
                {"name": "nebula:flutter-sdk", "value": flutter.group(1) if flutter else "unknown"}
            ],
        },
        "components": components,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--version", required=True, help="the release, e.g. 0.1.22")
    sys.stdout.write(json.dumps(build(parser.parse_args().version), indent=2) + "\n")


if __name__ == "__main__":
    main()
