"""Building the Xray driver, in a module that costs nothing to import.

This lived in main.py, which builds the FastAPI application at module scope
(`app = create_app()`). Anything importing the builder therefore constructed
the whole agent -- including the operation ledger, which reads its file on
construction -- as a side effect of an import.

That broke both monitoring commands, and broke them in the way that matters
most: `nebula-agent-alert` and `nebula-agent-healthcheck` run under units with
an empty CapabilityBoundingSet, so they have no CAP_DAC_OVERRIDE and root does
not bypass file permissions. Reading a ledger owned by nebula-agent failed
with EACCES, and the components whose entire job is reporting failures became
the things that failed.

Living here, the builder can be imported by the serving path and by anything
that only wants to ask the driver a question, with neither paying for the
other. main.py imports it too, so there is one definition rather than a copy
that can drift from what the agent actually serves.
"""

from nebula_agent.drivers.fake import FakeXrayRunner
from nebula_agent.drivers.xray import NativeXrayDriver
from nebula_agent.drivers.xray_base import XrayDriver
from nebula_agent.drivers.xray_config_store import XrayConfigStore
from nebula_agent.settings import Settings


def build_xray_driver(settings: Settings) -> XrayDriver:
    profiles = settings.build_xray_inbound_profiles()
    if settings.xray_driver == "fake":
        return FakeXrayRunner(
            server_address=settings.xray_public_host,
            sni=settings.xray_sni,
            profiles=profiles,
        )
    store = XrayConfigStore(settings.xray_state_dir, settings.xray_config_dir)
    return NativeXrayDriver(settings, store, profiles)
