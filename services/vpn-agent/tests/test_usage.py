"""Reading counters is easy to get subtly, silently wrong.

Nothing here fails loudly in production: a swapped direction shows plausible
numbers that are simply the wrong way round, a mis-sliced field shows a
handshake timestamp as a byte count, and a source that errors shows zero --
which looks exactly like a user who has not used the service. So each of those
gets a test.
"""

import asyncio
import json
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass

import pytest

from nebula_agent import usage
from nebula_agent.usage import (
    UsageSourceUnavailable,
    collect_hysteria_usage,
    collect_wireguard_usage,
    collect_xray_usage,
    digest_identity,
)

PEER_A = "AbwbuWf+Q09USVc9vs7z+cCRr5m44WIs4myRCT3IBFw="
PEER_B = "0md3RFB5UMEG3UmrmBKprZ+d8tgl5ugoYjknEkQ04AU="
CLIENT = "6f3b1c8e-1111-2222-3333-44444444d410"
STATS_URL = "http://127.0.0.1:25413/traffic"
STATS_ADDRESS = "127.0.0.1:25414"
STATS_SECRET = "test-only"  # noqa: S105 - fixture, not a credential


@dataclass
class FakeRun:
    returncode: int
    stdout: bytes
    stderr: bytes = b""


def _patch_run(monkeypatch: pytest.MonkeyPatch, result: FakeRun) -> list[list[str]]:
    calls: list[list[str]] = []

    async def fake_run(argv: list[str], **_kwargs: object) -> FakeRun:
        calls.append(list(argv))
        return result

    monkeypatch.setattr(usage, "run_fixed_argv", fake_run)
    return calls


class TestWireGuard:
    # `wg show <iface> dump`: the first line is the interface itself, then one
    # tab-separated line per peer:
    #   public-key  psk  endpoint  allowed-ips  handshake  rx  tx  keepalive
    DUMP = (
        "privkey\tpubkey\t51820\toff\n"
        f"{PEER_A}\t(none)\t1.2.3.4:1024\t10.0.0.2/32\t1757000000\t1024\t2048\toff\n"
        f"{PEER_B}\t(none)\t(none)\t10.0.0.3/32\t0\t0\t0\toff\n"
    )

    def test_reads_one_sample_per_peer_skipping_the_interface_line(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_run(monkeypatch, FakeRun(0, self.DUMP.encode()))
        samples = asyncio.run(collect_wireguard_usage(wg_binary="/usr/bin/wg", interface="wg0"))

        assert [s.identity for s in samples] == [
            digest_identity(PEER_A),
            digest_identity(PEER_B),
        ]
        # The interface line has no peer; counting it would invent a
        # credential whose key is a private key.
        assert all(s.protocol == "wireguard" for s in samples)

    def test_reads_the_transfer_columns_not_the_handshake(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Field 4 is a unix timestamp. Off by one and every user appears to
        # have transferred about 1.7 billion bytes.
        _patch_run(monkeypatch, FakeRun(0, self.DUMP.encode()))
        first = asyncio.run(collect_wireguard_usage(wg_binary="/usr/bin/wg", interface="wg0"))[0]

        assert first.rx_bytes == 1024
        assert first.tx_bytes == 2048

    def test_a_peer_that_has_never_connected_reports_zero_not_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_run(monkeypatch, FakeRun(0, self.DUMP.encode()))
        samples = asyncio.run(collect_wireguard_usage(wg_binary="/usr/bin/wg", interface="wg0"))

        idle = next(s for s in samples if s.identity == digest_identity(PEER_B))
        assert (idle.rx_bytes, idle.tx_bytes) == (0, 0)

    def test_a_failed_command_says_so_rather_than_reporting_no_traffic(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Returning [] here would be reported by the route as a source read
        # successfully with nothing to say, which is indistinguishable from
        # an interface nobody used. The poll still survives it -- the route
        # gathers each source separately.
        _patch_run(monkeypatch, FakeRun(1, b"", b"wg: interface not found"))

        with pytest.raises(UsageSourceUnavailable, match="wg9"):
            asyncio.run(collect_wireguard_usage(wg_binary="/usr/bin/wg", interface="wg9"))


class TestXray:
    STATS = json.dumps(
        {
            "stat": [
                {"name": f"user>>>{CLIENT}>>>traffic>>>uplink", "value": "111"},
                {"name": f"user>>>{CLIENT}>>>traffic>>>downlink", "value": "222"},
                # Inbound totals exist alongside user ones and are not
                # attributable to anybody.
                {"name": "inbound>>>vless-ws-tls>>>traffic>>>uplink", "value": "999"},
            ]
        }
    ).encode()

    def test_a_label_that_is_already_the_digest_is_not_hashed_again(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Clients are labelled with the digest now, so the credential never
        # appears in Xray's output. Hashing it a second time would attribute
        # every byte to nobody, silently.
        label = digest_identity(CLIENT)
        stats = json.dumps(
            {"stat": [{"name": f"user>>>{label}>>>traffic>>>uplink", "value": "5"}]}
        ).encode()
        _patch_run(monkeypatch, FakeRun(0, stats))

        samples = asyncio.run(
            collect_xray_usage(xray_binary="/usr/local/bin/xray", api_address=STATS_ADDRESS)
        )

        assert [sample.identity for sample in samples] == [label]

    def test_pairs_a_users_two_directions_into_one_sample(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_run(monkeypatch, FakeRun(0, self.STATS))
        samples = asyncio.run(
            collect_xray_usage(xray_binary="/usr/local/bin/xray", api_address=STATS_ADDRESS)
        )

        assert len(samples) == 1
        assert samples[0].identity == digest_identity(CLIENT)

    def test_uplink_is_what_the_server_received(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Xray names directions from the client's side. Swapping these shows
        # believable figures that are exactly backwards, which no amount of
        # looking at the app would reveal.
        _patch_run(monkeypatch, FakeRun(0, self.STATS))
        sample = asyncio.run(
            collect_xray_usage(xray_binary="/usr/local/bin/xray", api_address=STATS_ADDRESS)
        )[0]

        assert sample.rx_bytes == 111
        assert sample.tx_bytes == 222

    def test_ignores_counters_that_belong_to_no_user(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_run(monkeypatch, FakeRun(0, self.STATS))
        samples = asyncio.run(
            collect_xray_usage(xray_binary="/usr/local/bin/xray", api_address=STATS_ADDRESS)
        )

        assert all(s.identity == digest_identity(CLIENT) for s in samples)

    def test_unparseable_output_is_a_failed_source_not_an_idle_one(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_run(monkeypatch, FakeRun(0, b"not json at all"))

        with pytest.raises(UsageSourceUnavailable):
            asyncio.run(
                collect_xray_usage(xray_binary="/usr/local/bin/xray", api_address=STATS_ADDRESS)
            )


def test_no_sample_ever_carries_a_raw_identity() -> None:
    # The point of the digest. For VLESS and Hysteria2 the identity the
    # serving process reports is the credential itself, so a sample carrying
    # it in the clear would hand a second plaintext copy to everything
    # downstream -- including a database column that deliberately stores it
    # encrypted.
    digest = digest_identity(CLIENT)
    assert digest != CLIENT
    assert CLIENT not in digest
    assert len(digest) == 64


class TestHysteria:
    def test_swaps_hysterias_client_side_naming(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Hysteria reports tx/rx from the client's point of view: its `tx` is
        # the client uploading, which is the server receiving.
        monkeypatch.setattr(usage, "_fetch_json", _returning({CLIENT: {"tx": 500, "rx": 900}}))
        sample = asyncio.run(collect_hysteria_usage(api_url=STATS_URL, secret=STATS_SECRET))[0]

        assert sample.protocol == "hysteria2"
        assert sample.rx_bytes == 500
        assert sample.tx_bytes == 900

    def test_a_session_named_by_its_label_is_not_hashed_again(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # With HTTP auth, Hysteria names each session by the label the agent
        # admitted it as, which is already the digest.
        label = digest_identity(CLIENT)
        monkeypatch.setattr(usage, "_fetch_json", _returning({label: {"tx": 1, "rx": 2}}))

        sample = asyncio.run(collect_hysteria_usage(api_url=STATS_URL, secret=STATS_SECRET))[0]

        assert sample.identity == label

    def test_a_non_mapping_payload_is_a_failed_source(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Something is answering on that port, but it is not the endpoint we
        # think it is. Reporting zero traffic would hide that entirely.
        monkeypatch.setattr(usage, "_fetch_json", _returning(["unexpected"]))

        with pytest.raises(UsageSourceUnavailable):
            asyncio.run(collect_hysteria_usage(api_url=STATS_URL, secret=STATS_SECRET))

    def test_an_unreachable_endpoint_says_so(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # The failure that actually happened in production: nothing was
        # listening, and the poll reported the source as read.
        def raising(*_args: object, **_kwargs: object) -> object:
            raise OSError("connection refused")

        monkeypatch.setattr(usage, "_fetch_json", raising)

        with pytest.raises(UsageSourceUnavailable, match="connection refused"):
            asyncio.run(collect_hysteria_usage(api_url=STATS_URL, secret=STATS_SECRET))


def _returning(payload: object) -> Callable[..., object]:
    def fake(*_args: object, **_kwargs: object) -> object:
        return payload

    return fake


class TestWireGuardMalformedLines:
    def test_a_truncated_line_is_skipped_not_guessed_at(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # `wg show dump` gains columns between releases and loses them when a
        # peer is half-configured. Indexing blindly would read a keepalive or
        # an endpoint as a byte count.
        _patch_run(
            monkeypatch,
            FakeRun(0, f"privkey\tpubkey\t51820\toff\n{PEER_A}\t(none)\t1.2.3.4:1024\n".encode()),
        )

        assert asyncio.run(collect_wireguard_usage(wg_binary="/usr/bin/wg", interface="wg0")) == []

    def test_a_non_numeric_counter_is_skipped_rather_than_raising(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # One malformed peer must not cost every other peer on the interface
        # its sample.
        dump = (
            "privkey\tpubkey\t51820\toff\n"
            f"{PEER_A}\t(none)\t1.2.3.4:1024\t10.0.0.2/32\t1757000000\t(none)\t(none)\toff\n"
            f"{PEER_B}\t(none)\t(none)\t10.0.0.3/32\t0\t64\t128\toff\n"
        )
        _patch_run(monkeypatch, FakeRun(0, dump.encode()))

        samples = asyncio.run(collect_wireguard_usage(wg_binary="/usr/bin/wg", interface="wg0"))

        assert [sample.identity for sample in samples] == [digest_identity(PEER_B)]
        assert samples[0].rx_bytes == 64


class TestXrayFailures:
    def test_a_failed_query_says_so_rather_than_reporting_no_traffic(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Xray's stats API is only up once the config store has rendered the
        # listener, so a fresh host answers this way until the agent reloads.
        # That window has to be visible, not read as "nobody used anything".
        _patch_run(monkeypatch, FakeRun(1, b"", b"failed to dial"))

        with pytest.raises(UsageSourceUnavailable, match="failed to dial"):
            asyncio.run(
                collect_xray_usage(xray_binary="/usr/local/bin/xray", api_address=STATS_ADDRESS)
            )

    def test_an_unrecognised_direction_is_ignored(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Only uplink and downlink are directions. Anything else would land in
        # the totals dict as a third key and never be read.
        stats = json.dumps(
            {
                "stat": [
                    {"name": f"user>>>{CLIENT}>>>traffic>>>uplink", "value": "10"},
                    {"name": f"user>>>{CLIENT}>>>traffic>>>sideways", "value": "999"},
                ]
            }
        ).encode()
        _patch_run(monkeypatch, FakeRun(0, stats))

        sample = asyncio.run(
            collect_xray_usage(xray_binary="/usr/local/bin/xray", api_address=STATS_ADDRESS)
        )[0]

        assert sample.rx_bytes == 10
        assert sample.tx_bytes == 0


class TestHysteriaMalformedEntries:
    def test_a_non_mapping_entry_is_skipped_not_counted_as_zero(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A zero sample and no sample are different: the control plane treats
        # a reading below the last one as a restart, so an invented zero would
        # re-add the whole next reading to the total.
        monkeypatch.setattr(
            usage,
            "_fetch_json",
            _returning({CLIENT: "not-a-mapping", "other": {"tx": 5, "rx": 7}}),
        )

        samples = asyncio.run(collect_hysteria_usage(api_url=STATS_URL, secret=STATS_SECRET))

        assert [sample.identity for sample in samples] == [digest_identity("other")]


class TestFetchJson:
    def test_sends_the_secret_as_the_authorization_header(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Hysteria rejects an unauthenticated read, and a poll that silently
        # 401s looks exactly like a server nobody used.
        seen: dict[str, object] = {}

        # Patched on the shared stdlib module, which is the same object
        # `usage` resolves through at call time.
        monkeypatch.setattr(
            urllib.request, "urlopen", _fake_urlopen(seen, b'{"user": {"tx": 1, "rx": 2}}')
        )

        parsed = usage._fetch_json(STATS_URL, STATS_SECRET, 10)

        assert parsed == {"user": {"tx": 1, "rx": 2}}
        assert seen["Authorization"] == STATS_SECRET
        assert seen["url"] == STATS_URL
        assert seen["timeout"] == 10


class _FakeResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None


def _fake_urlopen(seen: dict[str, object], body: bytes) -> Callable[..., object]:
    def fake(request: object, timeout: float | None = None) -> object:
        # urllib title-cases header names it is given.
        seen["Authorization"] = request.get_header("Authorization")  # type: ignore[attr-defined]
        seen["url"] = request.full_url  # type: ignore[attr-defined]
        seen["timeout"] = timeout
        return _FakeResponse(body)

    return fake
