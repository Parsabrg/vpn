"""Drives the real app on a real Android device over adb: UI Automator dumps to
find what is on screen, taps by label, and network checks run by the device's
own shell (which the VPN carries like any other app).

No mocks: every check reads the live screen or makes a real request.
"""

from __future__ import annotations

import os
import re
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass

ADB = os.environ.get("ADB", "adb")
SERIAL = os.environ.get("ANDROID_SERIAL")
if not SERIAL:
    # With two devices attached adb refuses every unaddressed command, and a
    # run would record nothing but empty screens.
    _attached = [l.split()[0] for l in subprocess.run(
        [ADB, "devices"], capture_output=True, text=True).stdout.splitlines()[1:] if l.endswith("device")]
    if len(_attached) > 1:
        raise SystemExit(f"several devices attached {_attached}: set ANDROID_SERIAL")


def adb(*args: str, timeout: float = 60, check: bool = False) -> str:
    cmd = [ADB] + (["-s", SERIAL] if SERIAL else []) + list(args)
    env = dict(os.environ, MSYS_NO_PATHCONV="1")
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                             env=env, encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return ""
    if check and out.returncode != 0:
        raise RuntimeError(f"adb {' '.join(args)}: {out.stderr.strip()}")
    return out.stdout


def sh(command: str, timeout: float = 60) -> str:
    return adb("shell", command, timeout=timeout)


@dataclass
class Node:
    label: str
    cls: str
    bounds: tuple[int, int, int, int]
    checked: bool
    enabled: bool

    @property
    def center(self) -> tuple[int, int]:
        x1, y1, x2, y2 = self.bounds
        return (x1 + x2) // 2, (y1 + y2) // 2


def dump() -> list[Node]:
    """Every labelled node on screen. Flutter puts text in content-desc."""
    for _ in range(3):
        sh("uiautomator dump /sdcard/e2e.xml >/dev/null 2>&1", timeout=30)
        raw = sh("cat /sdcard/e2e.xml", timeout=30)
        if raw.startswith("<?xml"):
            break
        time.sleep(0.5)
    else:
        return []
    nodes: list[Node] = []
    for el in ET.fromstring(raw).iter("node"):
        label = (el.get("content-desc") or "") or (el.get("text") or "")
        b = re.findall(r"\d+", el.get("bounds", "[0,0][0,0]"))
        nodes.append(Node(label, el.get("class", ""), tuple(map(int, b)),  # type: ignore[arg-type]
                          el.get("checked") == "true", el.get("enabled") == "true"))
    return nodes


def labels() -> list[str]:
    return [n.label for n in dump() if n.label]


def find(pattern: str, nodes: list[Node] | None = None) -> Node | None:
    rx = re.compile(pattern, re.S)  # case matters: "DIAGNOSTICS" heading vs "Diagnostics" row
    for n in nodes if nodes is not None else dump():
        if n.label and rx.search(n.label):
            return n
    return None


def wait_for(pattern: str, timeout: float = 20) -> Node | None:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        n = find(pattern)
        if n:
            return n
        time.sleep(0.4)
    return None


def tap(pattern: str, timeout: float = 15) -> bool:
    n = wait_for(pattern, timeout)
    if not n:
        return False
    x, y = n.center
    sh(f"input tap {x} {y}")
    return True


def tap_xy(x: int, y: int) -> None:
    sh(f"input tap {x} {y}")


def type_text(text: str) -> None:
    # `input text` needs spaces as %s and shell metacharacters quoted.
    safe = text.replace("%", "%25").replace(" ", "%s")
    sh(f"input text '{safe}'")


def key(name: str) -> None:
    sh(f"input keyevent {name}")


def back() -> None:
    key("KEYCODE_BACK")


def screenshot(path: str) -> None:
    sh("screencap -p /sdcard/e2e.png", timeout=30)
    adb("pull", "/sdcard/e2e.png", path, timeout=60)


def foreground() -> str:
    out = sh("dumpsys activity activities | grep -m1 topResumedActivity")
    m = re.search(r"u0 (\S+)/", out)
    return m.group(1) if m else ""


def launch(package: str, cold: bool = True) -> None:
    if cold:
        sh(f"am force-stop {package}")
    sh(f"monkey -p {package} -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1")


# --- network, measured by the device itself ---------------------------------

def vpn_up() -> bool:
    """A VPN network is connected (its agent line reads `ni{VPN CONNECTED`)."""
    return "ni{VPN CONNECTED" in sh("dumpsys connectivity | grep 'ni{VPN'")


def curl(url: str, timeout: int = 20, extra: str = "") -> tuple[int, int, float, str]:
    """(http status, bytes received, seconds, body head) of a real request."""
    marker = "~E2E~"  # not @: curl reads -w @x as a file
    # No spaces inside the quoted -w: Windows argument quoting splits them
    # before the device shell sees the quotes.
    out = sh(f"curl -s -m {timeout} {extra} -w '{marker}%{{http_code}},%{{size_download}},%{{time_total}}' "
             f"'{url}' 2>/dev/null | tail -c 600", timeout=timeout + 15)
    if marker not in out:
        return 0, 0, float(timeout), ""
    body, stats = out.rsplit(marker, 1)
    try:
        code, size, secs = stats.strip().split(",")
        return int(code), int(size), float(secs), body.strip()[:200]
    except ValueError:
        return 0, 0, float(timeout), body.strip()[:200]


# Not behind Cloudflare: a Cloudflare Worker relay cannot reach Cloudflare's
# own addresses, so an echo hosted there reads as "no traffic" through it.
ECHO_HOST = "checkip.amazonaws.com"


def egress_ip(timeout: int = 15) -> str:
    code, _, _, body = curl(f"https://{ECHO_HOST}", timeout)
    body = body.strip()
    if code == 200 and re.fullmatch(r"[\d.]+", body):
        return body
    if "not found" in sh("command -v curl || echo not found"):
        # Emulator images ship no curl: plain HTTP through toybox nc.
        req = "printf 'GET / HTTP/1.0\\r\\nHost: checkip.amazonaws.com\\r\\n\\r\\n'"
        raw = sh(f"{req} | toybox nc -q {timeout} -w {timeout} {ECHO_HOST} 80", timeout=timeout + 10)
        m = re.search(r"\n\r?\n([\d.]+)\s*$", raw)
        return m.group(1) if m else ""
    return ""


def egress_ip6(timeout: int = 10) -> str:
    code, _, _, body = curl("https://api6.ipify.org", timeout, "-6")
    return body if code == 200 and ":" in body else ""
