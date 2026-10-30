"""Process entrypoint: serves the agent under uvicorn with mutual TLS.

uvicorn terminates TLS directly rather than a local reverse proxy in front of
it -- the agent is a loopback/private-interface-only service per the threat
model, so a separate TLS terminator would add attack surface and an extra
hardened unit for no isolation benefit. The tradeoff: certificate rotation
needs a process restart (systemd Restart=on-failure handles this), which
docs/threat-model.md already accepts as residual risk.
"""

import ssl

import uvicorn

from nebula_agent.main import create_app
from nebula_agent.settings import Settings, get_settings


def build_uvicorn_config(settings: Settings) -> uvicorn.Config:
    """Builds the server configuration without binding a socket or reading
    certificate files -- both happen lazily on Server.run(), which keeps this
    testable."""

    return uvicorn.Config(
        create_app(settings),
        host=settings.agent_bind_host,
        port=settings.agent_bind_port,
        access_log=False,
        ssl_certfile=str(settings.agent_tls_cert_file),
        ssl_keyfile=str(settings.agent_tls_key_file),
        ssl_ca_certs=str(settings.agent_trusted_client_ca_file),
        ssl_cert_reqs=ssl.CERT_REQUIRED,
    )


def main() -> None:
    uvicorn.Server(build_uvicorn_config(get_settings())).run()


if __name__ == "__main__":
    main()
