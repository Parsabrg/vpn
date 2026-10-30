# End-to-end tests on a real device

These drive the installed app through its screen over adb (UI Automator
dumps and taps) and judge each result by what the device itself sees: a
connected VPN network, the exit address an outside echo reports, bytes
actually downloaded. No mocks; nothing here passes on a "Protected" label
alone.

## What you need

- A phone (or emulator) with USB debugging, signed in to a server, or in
  free mode. `adb devices` lists it; with several attached, set
  `ANDROID_SERIAL`.
- The app installed and VPN permission granted once by hand (Android's
  consent dialog is the person's decision, so the tests do not answer it).
- Python 3.11+ on the computer. No packages beyond the standard library.
- The phone kept awake while plugged in (the suites set `svc power stayon
  usb` and reset it at the end).

## Suites

| Command | What it does | Time |
|---|---|---|
| `python nebula_e2e.py --suite live` | Each protocol through the UI: connect, VPN up, exit = server, 5 MB HTTPS, plain HTTP, five HTTPS round trips, ad domain blocked on `-adblock` profiles, disconnect restores the direct exit | ~1 min per protocol |
| `python nebula_e2e.py --suite stress --cycles 20 --proto vless-xhttp-tls` | 20 connect/disconnect cycles, ten rapid taps, 20 protocol switches while connected | ~20 min |
| `python nebula_e2e.py --suite network --proto vless-xhttp-tls` | Wi-Fi off/on, airplane mode, Wi-Fi to mobile data and back, screen off with forced Doze, background, the system killing the app | ~10 min |
| `python nebula_e2e.py --suite soak --minutes 30` | A session in the background with a 1 MB download every 20 s; memory sampled | as given |
| `python free_mode_e2e.py` | Free mode on a fresh install: malformed and unsafe links, http / failing / empty subscriptions, an unreachable server | ~5 min |

Every suite ends by checking logcat for crashes, ANRs and credentials in
the app's own lines.

Options: `--out DIR` (results, screenshots, logcat), `--protocols a,b,c`
(live), `--proto` (the protocol stress/network/soak use). Environment:
`NEBULA_PACKAGE` (e.g. `org.nebulavpn.nebula_mobile.e2e` for a build with
`-P nebula.applicationIdSuffix=.e2e`), `NEBULA_SERVER_EXIT` (the server's
public address; empty for a relay, where any exit but the device's own
counts).

## Output

`DIR/results.json` and `DIR/results.md`: each test with expected, actual,
PASS / FAIL / BLOCKED and evidence; the pass rate counts executed tests
only. Screenshots in `DIR/screens/`, logcat in `DIR/logcat*.txt`. A failure
is recorded and the next test runs; every step has a timeout.

## Running unattended

The computer has to stay awake and the phone plugged in; a sleeping laptop
stops the run. Run each suite under `timeout` (the suites' own limits stop
a hung step, `timeout` stops a hung adb). Nothing needs a person once VPN
consent has been given, except the network suite's mobile-data step, which
is skipped (BLOCKED) on a phone without a SIM.

## Limits

- Screen reads take about a second each, so times measured here include
  that; the app's own connect time is shorter (2-4 s on the test phone,
  from in-app timing).
- `adb shell` traffic is the shell's (uid 2000), which the VPN carries
  like any app's; per-app split tunnelling is not exercised by it.
- Android's always-on VPN and "Block connections without VPN" are system
  settings the tests do not change.
