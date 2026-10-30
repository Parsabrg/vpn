"""Free mode (no server, no account) on a fresh install, usually an emulator.

Covers what a person without a server meets: adding links and subscriptions
(good, malformed, unsafe, unreachable), connecting through the built-in
relay, and what the screen says when something fails. Results are appended
to the same results.json as nebula_e2e.py.

    ANDROID_SERIAL=emulator-5560 NEBULA_PACKAGE=org.nebulavpn.nebula_mobile.e2e \\
        python free_mode_e2e.py --out results/
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

import nebula_e2e as e
import ui

DEAD_LINK = ("vless://0f1e2d3c-4b5a-4978-8a6b-5c4d3e2f1a0b@10.255.255.1:443"
             "?security=tls&type=ws&sni=dead.example.com&path=%2F#DeadServer")
INSECURE_LINK = ("vless://0f1e2d3c-4b5a-4978-8a6b-5c4d3e2f1a0b@1.2.3.4:443"
                 "?security=tls&type=ws&sni=x.example.com&allowInsecure=1#Insecure")


def free_tab() -> None:
    e.to_connect_tab()
    ui.tap(r"^Free\nFree$", timeout=5)
    time.sleep(1.2)


def hide_keyboard() -> None:
    # Back closes the keyboard when it is up; when it is not, Back would
    # leave the screen (and Escape closes the app), so ask first.
    if "mInputShown=true" in ui.sh("dumpsys input_method | grep mInputShown"):
        ui.back()
        time.sleep(0.5)


def _field(index: int):
    """The text field for links (0) or subscriptions (1) and its Add button,
    scrolled into view with the keyboard closed. The subscription field is
    the one below the "Subscriptions" heading."""
    hide_keyboard()
    ui.sh("input swipe 540 700 540 1800 300")  # top first
    time.sleep(0.6)
    for _ in range(4):
        nodes = ui.dump()
        heading = next((n for n in nodes if n.label == "Subscriptions"), None)
        split = heading.bounds[1] if heading else 10_000
        pairs = [(f, a) for f in nodes if "EditText" in f.cls
                 for a in nodes if a.label == "Add" and abs(a.center[1] - f.center[1]) < 80]
        for f, a in pairs:
            if (f.bounds[1] > split) == (index == 1):
                return f, a
        ui.sh("input swipe 540 1600 540 1000 300")
        time.sleep(0.6)
    raise RuntimeError(f"field {index} not found")


def fill_and_add(index: int, text: str) -> list[str]:
    """Types into a field of the Free tab and presses its Add."""
    field, _ = _field(index)
    ui.tap_xy(*field.center)
    time.sleep(0.3)
    ui.key("KEYCODE_MOVE_END")
    ui.sh("input keyevent " + " ".join(["67"] * 250))  # delete what is there
    ui.type_text(text)
    hide_keyboard()
    time.sleep(0.6)
    _, add = _field(index)
    ui.tap_xy(*add.center)
    time.sleep(4)
    return ui.labels()


def case(tid: str, title: str, expected: str, ok: bool, actual: str, **ev) -> None:
    e.record(e.Result(tid, title, "PASS" if ok else "FAIL", expected, actual, evidence=ev))


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--out", default="results")
    a = p.parse_args()
    e.OUT = Path(a.out)

    free_tab()
    labels = fill_and_add(0, "vless://garbage")
    case("FREE-1", "Malformed link is refused with an explanation",
         "error naming the accepted link types", any("cannot be used" in l for l in labels),
         next((l for l in labels if "cannot be used" in l), "no message")[:90])

    labels = fill_and_add(0, INSECURE_LINK)
    case("FREE-2", "Link that turns off certificate checks is refused",
         "refused, not added", any("cannot be used" in l for l in labels), "refused" if any("cannot be used" in l for l in labels) else "accepted")

    labels = fill_and_add(1, "http://example.com/sub")
    case("FREE-3", "Subscription over plain http is refused", "asks for https://",
         any("https://" in l and "Use" in l for l in labels),
         next((l for l in labels if "https://" in l and "Use" in l), "no message"))

    labels = fill_and_add(1, "https://httpbin.org/status/500")
    time.sleep(8)
    labels = ui.labels()
    msg = next((l for l in labels if "refused" in l or "reach" in l or "Not fetched" in l), "")
    case("FREE-4", "Subscription whose server answers 500", "says it refused; nothing else breaks",
         "refused" in msg or "reach" in msg, msg or "no status shown", screen=e.shot("FREE-4"))

    labels = fill_and_add(1, "https://www.google.com/generate_204")
    time.sleep(8)
    labels = ui.labels()
    msg = next((l for l in labels if "No connection" in l or "refused" in l or "reach" in l), "")
    case("FREE-5", "Subscription that is empty", "says it holds nothing usable",
         "No connection" in msg, msg or "no status shown", screen=e.shot("FREE-5"))

    labels = fill_and_add(0, DEAD_LINK)
    added = any("DeadServer" in l for l in labels)
    e.to_connect_tab()
    ui.tap(r"^Server\n", timeout=5)
    time.sleep(1.5)
    picked = ui.tap(r"^DeadServer", timeout=5)
    if picked:
        ui.tap(r"^Use ", timeout=5)
        time.sleep(1)
    st, secs = e.connect(90)
    vpn = ui.vpn_up()
    labels = ui.labels()
    case("FREE-6", "Connecting to an unreachable server",
         "never Protected; a failure the person can act on; no VPN left up",
         added and picked and st != "protected" and not vpn,
         f"added {added}, picked {picked}, UI '{st}' after {secs}s, VPN up {vpn}; "
         + next((l for l in labels if len(l) > 40), ""), screen=e.shot("FREE-6"))
    if vpn:
        e.disconnect()


if __name__ == "__main__":
    main()
