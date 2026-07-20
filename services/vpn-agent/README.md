# Nebula VPN agent

Host-side FastAPI service for allowlisted VPN driver operations. In Phase 1.1 it
exposes only non-sensitive liveness and readiness probes. It has no endpoint for
shell commands, executable paths, raw WireGuard configuration, raw Xray JSON, or
user authentication.

The production agent will run as a hardened systemd service with narrowly scoped
capabilities and mTLS. The included non-root container is only for scaffold smoke
testing; it deliberately has no network-administration capability.

## Development

```shell
python -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/ruff check .
.venv/bin/mypy
.venv/bin/pytest
.venv/bin/uvicorn nebula_agent.main:app --reload --port 9443
```

On Windows, replace `.venv/bin/` with `.venv\\Scripts\\`.
