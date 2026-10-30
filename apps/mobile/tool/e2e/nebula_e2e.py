"""End-to-end tests of the installed Nebula app on a real Android device.

Every test drives the app through its screen (UI Automator over adb) and
judges the outcome by what the device itself observes: a VPN network that is
up, the address the internet sees, bytes actually downloaded. A "Protected"
label alone never passes a test.

    python nebula_e2e.py --suite live --out results/      # tunnel tests
    python nebula_e2e.py --suite stress --cycles 20        # connect cycles
    python nebula_e2e.py --suite network                   # Wi-Fi loss etc.
    python nebula_e2e.py --suite soak --minutes 30         # long session

Results go to <out>/results.json and <out>/results.md, screenshots and
logcat beside them. Each test has its own timeout; a failure is recorded and
the next test runs. See README.md for the environment it needs.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import statistics
import sys
import time
import traceback
from dataclasses import asdict, dataclass, field
from pathlib import Path

import ui

PACKAGE = os.environ.get("NEBULA_PACKAGE", "org.nebulavpn.nebula_mobile")
SERVER_EXIT = os.environ["NEBULA_SERVER_EXIT"]  # the server's public IPv4
# Set at the start of a run: the device's own exit, with no VPN.
DIRECT_EXIT = ""


def through_vpn(ip: str) -> bool:
    """The exit is the tunnel's: the server's, or with NEBULA_SERVER_EXIT
    empty (a relay whose exit address varies) anything but the direct one."""
    return ip == SERVER_EXIT if SERVER_EXIT else bool(ip) and ip != DIRECT_EXIT
DOWNLOAD = "https://speed.cloudflare.com/__down?bytes=5000000"
PLAIN_HTTP = "http://neverssl.com/"
AD_DOMAIN = "https://doubleclick.net/"
# Docker Hub refuses Iranian addresses with 403; through the server it answers.
SANCTIONED = "https://hub.docker.com/v2/repositories/library/alpine/"

OUT = Path("results")
# --no-wifi: mobile data only (a Wi-Fi the phone should not rejoin nearby).
NO_WIFI = False


@dataclass
class Result:
    id: str
    title: str
    status: str = "BLOCKED"  # PASS | FAIL | BLOCKED
    expected: str = ""
    actual: str = ""
    seconds: float = 0.0
    evidence: dict = field(default_factory=dict)


RESULTS: list[Result] = []


def record(r: Result) -> Result:
    RESULTS.append(r)
    print(f"[{r.status:7}] {r.id} {r.title}: {r.actual}", flush=True)
    save()
    return r


def save() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "results.json").write_text(json.dumps([asdict(r) for r in RESULTS], indent=2))
    ran = [r for r in RESULTS if r.status != "BLOCKED"]
    passed = sum(r.status == "PASS" for r in ran)
    lines = [
        "| ID | Test | Status | Actual |",
        "|---|---|---|---|",
        *[f"| {r.id} | {r.title} | {r.status} | {r.actual.replace('|', '/')} |" for r in RESULTS],
        "",
        f"Executed {len(ran)}, passed {passed}"
        + (f" ({100 * passed / len(ran):.0f}%)" if ran else "")
        + f"; blocked {len(RESULTS) - len(ran)}.",
    ]
    (OUT / "results.md").write_text("\n".join(lines), encoding="utf-8")


def shot(name: str) -> str:
    path = OUT / "screens" / f"{name}.png"
    path.parent.mkdir(parents=True, exist_ok=True)
    ui.screenshot(str(path))
    return str(path)


# --- app actions, through the screen ----------------------------------------

def to_connect_tab() -> None:
    if ui.foreground() != PACKAGE:
        ui.launch(PACKAGE, cold=False)
        time.sleep(2)
    ui.tap(r"^Connect\nConnect$", timeout=5)
    time.sleep(0.8)
    # A screen pushed over the tab (Servers, Your links) keeps the tab bar;
    # the connect screen itself is the one with the wordmark.
    for _ in range(4):
        if ui.find(r"^NEBULA$"):
            break
        ui.back()
        time.sleep(0.8)


def state() -> str:
    """What the connect screen says: protected, connecting, off, or other."""
    labels = ui.labels()
    joined = "\n".join(labels)
    if "Protected" in labels:
        return "protected"
    if re.search(r"Connecting|HANDSHAKE", joined):
        return "connecting"
    if re.search(r"^(Off|DISCONNECTED)$", joined, re.M):
        return "off"
    if re.search(r"Not protected|No connection|Unreachable|Retry tunnel", joined):
        return "failed"
    return "other"


def settle() -> None:
    """Back to Off from a connect that is still going (a stuck Connecting)."""
    to_connect_tab()
    if state() == "connecting":
        ui.tap(r"^Cancel$", timeout=3)
        for _ in range(30):
            if state() != "connecting":
                break
            time.sleep(1)
    if ui.vpn_up():
        disconnect()


def choose_protocol(name: str) -> bool:
    settle()
    if not ui.tap(r"^Protocol\n", timeout=6):
        return False
    time.sleep(1)
    rx = rf"^{re.escape(name)}$"
    for _ in range(4):
        if ui.tap(rx, timeout=2):
            break
        ui.sh("input swipe 636 2000 636 1300 300")
        time.sleep(0.6)
    else:
        ui.back()
        return False
    time.sleep(0.5)
    ok = ui.tap(r"^Use ", timeout=5)
    time.sleep(1)
    return ok


def connect(timeout: float = 45) -> tuple[str, float]:
    """Taps Connect; (final state, seconds until it settled)."""
    to_connect_tab()
    if state() == "protected":
        return "protected", 0.0
    start = time.monotonic()
    # After a failure the same button reads "Retry tunnel".
    ui.tap(r"^(Connect|Retry tunnel)$", timeout=5)
    seen = "other"
    while time.monotonic() - start < timeout:
        seen = state()
        if seen in ("protected", "failed"):
            break
        time.sleep(0.5)
    return seen, round(time.monotonic() - start, 1)


def disconnect(timeout: float = 20) -> tuple[bool, float]:
    to_connect_tab()
    start = time.monotonic()
    if not ui.tap(r"^(Disconnect|Cancel|Turn off VPN)$", timeout=5):
        return state() == "off" and not ui.vpn_up(), 0.0
    while time.monotonic() - start < timeout:
        if not ui.vpn_up() and state() == "off":
            return True, round(time.monotonic() - start, 1)
        time.sleep(0.5)
    return False, round(time.monotonic() - start, 1)


def traffic_check(expect_exit: str | None = SERVER_EXIT) -> dict:
    """The device's own view: VPN network, exit address, real bytes."""
    ev: dict = {"vpn_network": ui.vpn_up()}
    ev["exit_ip"] = ui.egress_ip()
    code, size, secs, _ = ui.curl(DOWNLOAD, timeout=40)
    ev["https_download"] = {"status": code, "bytes": size, "seconds": secs,
                            "mbps": round(size * 8 / secs / 1e6, 2) if size and secs else 0}
    code, size, secs, body = ui.curl(PLAIN_HTTP, timeout=20)
    ev["http_plain"] = {"status": code, "bytes": size, "neverssl": "NeverSSL" in body or size > 500}
    lat = []
    for _ in range(5):
        c, _, s, _ = ui.curl("https://www.google.com/generate_204", timeout=10)
        if c == 204:
            lat.append(s)
    ev["https_204_seconds"] = lat
    ev["exit_ip6"] = ui.egress_ip6()
    ok = (ev["vpn_network"]
          and (expect_exit is None or ev["exit_ip"] == expect_exit)
          and ev["https_download"]["bytes"] == 5_000_000
          and ev["http_plain"]["status"] == 200
          and len(lat) >= 4)
    ev["ok"] = bool(ok)
    return ev


# --- suites -----------------------------------------------------------------

PROTOCOLS = [
    "vless-ws-tls", "vless-grpc-tls", "vless-xhttp-tls", "vless-tcp-tls",
    "hysteria2", "wireguard-native", "Automatic",
    "vless-ws-tls-adblock", "vless-xhttp-tls-adblock", "hysteria2-adblock",
    "wireguard-native-adblock", "vless-grpc-tls-adblock", "vless-tcp-tls-adblock",
]


def suite_live(protocols: list[str]) -> None:
    disconnect()
    base = ui.egress_ip()
    record(Result("NET-0", "Baseline without VPN", "PASS" if base else "FAIL",
                  "a direct exit address", f"direct exit {base or 'none'}",
                  evidence={"exit_ip": base}))
    for proto in protocols:
        tid = f"VPN-{proto}"
        r = Result(tid, f"Connect and carry traffic: {proto}",
                   expected=f"Protected, VPN network up, exit {SERVER_EXIT}, 5 MB downloaded, "
                            "plain HTTP 200, disconnect restores direct")
        t0 = time.monotonic()
        try:
            if not choose_protocol(proto):
                r.status, r.actual = "FAIL", "could not select the protocol in the UI"
                record(r)
                continue
            # Hysteria2 and WireGuard are UDP; give the app's own give-up time
            # room, so "stuck" is the app's verdict and not this timeout.
            st, secs = connect(150 if proto.startswith(("hysteria", "wireguard")) else 60)
            r.evidence["ui_state"], r.evidence["connect_seconds"] = st, secs
            r.evidence["screen"] = shot(f"{tid}-connected")
            ev = traffic_check() if st == "protected" else {"ok": False, "vpn_network": ui.vpn_up(),
                                                            "exit_ip": ui.egress_ip()}
            r.evidence.update(ev)
            if proto.endswith("-adblock") and st == "protected":
                c, _, _, _ = ui.curl(AD_DOMAIN, timeout=10)
                r.evidence["ad_domain_status"] = c
                ev["ok"] = ev["ok"] and c == 0
            down, dsecs = disconnect()
            r.evidence["disconnected"], r.evidence["disconnect_seconds"] = down, dsecs
            after = ui.egress_ip()
            r.evidence["exit_after_disconnect"] = after
            if ev.get("ok") and down and after and after != SERVER_EXIT:
                d = ev["https_download"]
                r.status = "PASS"
                r.actual = (f"protected in {secs}s, exit {ev['exit_ip']}, 5 MB at {d['mbps']} Mbps, "
                            f"median 204 {statistics.median(ev['https_204_seconds']):.2f}s"
                            + (", ad domain blocked" if proto.endswith("-adblock") else "")
                            + f", off in {dsecs}s")
            else:
                r.status = "FAIL"
                if st != "protected":
                    r.actual = f"UI ended '{st}' after {secs}s; VPN network {r.evidence.get('vpn_network')}"
                elif ev.get("exit_ip") != SERVER_EXIT:
                    r.actual = f"UI says Protected but exit is '{ev.get('exit_ip')}'"
                else:
                    r.actual = f"traffic check failed: {json.dumps({k: ev[k] for k in ev if k != 'ok'})[:300]}"
        except Exception as e:  # keep going; the trace is the evidence
            r.status, r.actual = "FAIL", f"harness error {e!r}"
            r.evidence["trace"] = traceback.format_exc()
        r.seconds = round(time.monotonic() - t0, 1)
        record(r)
        settle()


def suite_stress(cycles: int, proto: str) -> None:
    choose_protocol(proto)
    times, ok, stuck = [], 0, 0
    for i in range(cycles):
        st, secs = connect(40)
        good = st == "protected" and through_vpn(ui.egress_ip())
        ok += good
        times.append(secs)
        if st == "connecting":
            stuck += 1
        down, _ = disconnect()
        if not down:
            stuck += 1
    record(Result("STRESS-1", f"{cycles} connect/disconnect cycles ({proto})",
                  "PASS" if ok == cycles and stuck == 0 else "FAIL",
                  "every cycle protected with the server's exit, every disconnect clean",
                  f"{ok}/{cycles} verified, {stuck} stuck, connect median "
                  f"{statistics.median(times):.1f}s max {max(times):.1f}s",
                  evidence={"connect_seconds": times}))
    # Rapid taps: Connect then Disconnect at once, repeatedly.
    to_connect_tab()
    for _ in range(10):
        ui.tap(r"^(Connect|Disconnect|Cancel)$", timeout=3)
        time.sleep(0.3)
    time.sleep(8)
    final = state()
    vpn = ui.vpn_up()
    consistent = (final == "protected") == vpn and final in ("protected", "off")
    record(Result("STRESS-2", "Ten rapid Connect/Disconnect taps", "PASS" if consistent else "FAIL",
                  "settles in a state the network agrees with",
                  f"UI '{final}', VPN network {vpn}", evidence={"screen": shot("STRESS-2")}))
    disconnect()
    # The way a person switches: the Connect screen's rows are read-only
    # while connected, so Disconnect, choose, Connect.
    names = ["vless-ws-tls", "vless-grpc-tls", "vless-xhttp-tls", "Automatic"]
    switches, good, secs = 0, 0, []
    for i in range(20):
        if not choose_protocol(names[i % len(names)]):
            continue
        switches += 1
        st, took = connect(40)
        secs.append(took)
        if st == "protected" and through_vpn(ui.egress_ip()):
            good += 1
    record(Result("STRESS-3", "20 consecutive protocol switches (disconnect, choose, connect)",
                  "PASS" if good == 20 else "FAIL",
                  "each switch ends protected with the server's exit",
                  f"{good}/{switches} verified ({20 - switches} could not be selected)",
                  evidence={"connect_seconds": secs}))
    disconnect()


def suite_network(proto: str) -> None:
    choose_protocol(proto)
    st, _ = connect()
    if st != "protected":
        record(Result("NETLOSS-0", "Connect before network tests", "FAIL", actual=st))
        return

    def recovered(limit: float) -> tuple[bool, float]:
        t = time.monotonic()
        while time.monotonic() - t < limit:
            if ui.egress_ip(8) == SERVER_EXIT:
                return True, round(time.monotonic() - t, 1)
            time.sleep(2)
        return False, round(time.monotonic() - t, 1)

    steps = [
        ("NETLOSS-1", "Wi-Fi off for 20 s, then back", "svc wifi disable", "svc wifi enable"),
        ("NETLOSS-2", "Airplane mode for 20 s, then back", "cmd connectivity airplane-mode enable",
         "cmd connectivity airplane-mode disable"),
    ]
    if NO_WIFI:
        steps = steps[1:]
    for tid, title, off, on in steps:
        ui.sh(off)
        time.sleep(20)
        leaked = ui.egress_ip(6)
        ui.sh(on)
        ok, secs = recovered(120)
        record(Result(tid, title, "PASS" if ok else "FAIL",
                      "traffic through the server again without touching the app",
                      f"recovered in {secs}s" if ok else f"not recovered after {secs}s; UI '{state()}'",
                      evidence={"exit_while_down": leaked}))
    # Wi-Fi to mobile data and back, when the phone has a SIM with data.
    if NO_WIFI:
        pass
    else:
        _wifi_to_mobile(recovered)
    _after_network(recovered)


def _wifi_to_mobile(recovered) -> None:
    ui.sh("svc wifi disable")
    time.sleep(5)
    cell = "MOBILE" in ui.sh("dumpsys connectivity | grep -m1 'ni{MOBILE'")
    if cell:
        ok, secs = recovered(90)
        ui.sh("svc wifi enable")
        ok2, secs2 = recovered(90)
        record(Result("NETLOSS-3", "Wi-Fi -> mobile data -> Wi-Fi while connected",
                      "PASS" if ok and ok2 else "FAIL", "carries traffic on each network",
                      f"mobile {'ok' if ok else 'failed'} in {secs}s, Wi-Fi {'ok' if ok2 else 'failed'} in {secs2}s"))
    else:
        ui.sh("svc wifi enable")
        record(Result("NETLOSS-3", "Wi-Fi -> mobile data -> Wi-Fi", "BLOCKED", actual="no mobile data network"))


def _after_network(recovered) -> None:
    time.sleep(10)
    # Screen off for two minutes (Doze is forced so the radio sleeps too).
    ui.key("KEYCODE_SLEEP")
    ui.sh("dumpsys deviceidle force-idle")
    time.sleep(120)
    ui.sh("dumpsys deviceidle unforce")
    ui.key("KEYCODE_WAKEUP")
    ok, secs = recovered(60)
    record(Result("DOZE-1", "Screen off and Doze for 2 minutes", "PASS" if ok else "FAIL",
                  "tunnel carries traffic after waking", f"carrying after {secs}s" if ok else "not carrying"))
    # Background, then back.
    ui.key("KEYCODE_HOME")
    time.sleep(30)
    bg_ok = ui.egress_ip() == SERVER_EXIT
    ui.launch(PACKAGE, cold=False)
    time.sleep(3)
    record(Result("BG-1", "App in background 30 s, then reopened", "PASS" if bg_ok and state() == "protected" else "FAIL",
                  "traffic through the server in background; reopened screen says Protected",
                  f"background exit ok={bg_ok}, screen '{state()}'"))
    # The app's process killed while connected.
    pid_before = ui.sh(f"pidof {PACKAGE}").strip()
    ui.sh(f"am kill {PACKAGE}")  # kills only a background process, as the system would
    time.sleep(5)
    kept = ui.egress_ip() == SERVER_EXIT
    record(Result("KILL-1", "System kills the backgrounded app while connected", "PASS" if kept else "FAIL",
                  "the VPN service keeps carrying traffic", f"exit through server: {kept}",
                  evidence={"pid_before": pid_before, "pid_after": ui.sh(f"pidof {PACKAGE}").strip()}))
    disconnect()


def suite_soak(minutes: int, proto: str) -> None:
    choose_protocol(proto)
    st, _ = connect()
    if st != "protected":
        record(Result("SOAK-1", f"{minutes}-minute session", "FAIL", actual=f"could not connect: {st}"))
        return
    ui.key("KEYCODE_HOME")
    end = time.monotonic() + minutes * 60
    probes, failures, total_bytes, mem = 0, [], 0, []
    while time.monotonic() < end:
        code, size, secs, _ = ui.curl("https://speed.cloudflare.com/__down?bytes=1000000", timeout=30)
        probes += 1
        total_bytes += size
        if code != 200 or size != 1_000_000:
            failures.append({"at_min": round((minutes * 60 - (end - time.monotonic())) / 60, 1), "code": code})
        pss = re.search(r"TOTAL PSS:\s+(\d+)", ui.sh(f"dumpsys meminfo {PACKAGE} | grep 'TOTAL PSS'"))
        if pss:
            mem.append(int(pss.group(1)))
        time.sleep(20)
    exit_ok = ui.egress_ip() == SERVER_EXIT
    rate = 100 * (probes - len(failures)) / probes if probes else 0
    record(Result("SOAK-1", f"{minutes}-minute continuous session ({proto})",
                  "PASS" if rate >= 98 and exit_ok else "FAIL",
                  "at least 98% of 1 MB downloads complete; still through the server at the end",
                  f"{probes - len(failures)}/{probes} downloads ({rate:.1f}%), {total_bytes / 1e6:.0f} MB, "
                  f"exit ok {exit_ok}, app PSS {mem[0] if mem else '?'} -> {mem[-1] if mem else '?'} KB",
                  evidence={"failures": failures, "pss_kb": mem}))
    ui.launch(PACKAGE, cold=False)
    disconnect()


def suite_logs() -> None:
    log = ui.adb("logcat", "-d", "-v", "time", timeout=120)
    # Only the app's own lines: other apps log their own tokens, and those
    # are not this app's leak. By process id -- `logcat --uid` is ignored on
    # some vendor builds (seen on ColorOS 16).
    pids = set(re.findall(r"^\S+\s+(\d+)", ui.sh(f"ps -A -o USER,PID,NAME | grep {PACKAGE}"), re.M))
    own = "\n".join(l for l in log.splitlines()
                     if any(f"( {p})" in l or f"({p})" in l for p in pids) or PACKAGE in l)
    (OUT / "logcat-app.txt").write_text(own, encoding="utf-8", errors="replace")
    (OUT / "logcat.txt").write_text(log, encoding="utf-8", errors="replace")
    crashes = re.findall(r"FATAL EXCEPTION.*?\n.*?Process: (\S+)", log)
    ours = [c for c in crashes if "nebula" in c]
    anrs = [l for l in log.splitlines() if "ANR in" in l and "nebula" in l]
    record(Result("LOG-1", "No crash or ANR of the app during the run", "PASS" if not ours and not anrs else "FAIL",
                  "no FATAL EXCEPTION or ANR for the app", f"{len(ours)} crashes, {len(anrs)} ANRs"))
    secrets = re.findall(r"(vless://\S+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|"
                         r"password=\S+|PrivateKey\s*=\s*\S+)", own, re.I)
    record(Result("LOG-2", "No credentials in the system log", "PASS" if not secrets else "FAIL",
                  "no VLESS links, UUIDs, passwords or private keys in logcat",
                  f"{len(secrets)} matches" + (f", e.g. {secrets[0][:12]}..." if secrets else "")))


def main() -> int:
    global OUT
    p = argparse.ArgumentParser()
    p.add_argument("--suite", choices=["live", "stress", "network", "soak", "logs", "all"], default="live")
    p.add_argument("--out", default="results")
    p.add_argument("--protocols", default=",".join(PROTOCOLS))
    p.add_argument("--proto", default="vless-ws-tls")
    p.add_argument("--cycles", type=int, default=20)
    p.add_argument("--minutes", type=int, default=30)
    p.add_argument("--no-wifi", action="store_true", help="leave Wi-Fi off throughout")
    a = p.parse_args()
    OUT = Path(a.out)
    global NO_WIFI
    NO_WIFI = a.no_wifi
    if os.path.exists(OUT / "results.json"):
        RESULTS.extend(Result(**d) for d in json.loads((OUT / "results.json").read_text()))
    global DIRECT_EXIT
    ui.adb("logcat", "-c")
    if not ui.vpn_up():
        DIRECT_EXIT = ui.egress_ip()
    ui.sh("svc power stayon usb")  # the screen stays on while plugged in, for the dumps
    try:
        if a.suite in ("live", "all"):
            suite_live(a.protocols.split(","))
        if a.suite in ("stress", "all"):
            suite_stress(a.cycles, a.proto)
        if a.suite in ("network", "all"):
            suite_network(a.proto)
        if a.suite in ("soak", "all"):
            suite_soak(a.minutes, a.proto)
    finally:
        suite_logs()
        ui.sh("svc power stayon false")
        if not NO_WIFI:
            ui.sh("svc wifi enable")
        ui.sh("cmd connectivity airplane-mode disable")
    return 0 if all(r.status != "FAIL" for r in RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
