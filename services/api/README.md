# Nebula API

Unprivileged FastAPI control-plane service. This Phase 1.1 scaffold exposes only
liveness and readiness probes; business and provisioning APIs are added in later
milestones. The container has no host, Docker socket, or VPN secret mounts.

## Development

```shell
python -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/ruff check .
.venv/bin/mypy
.venv/bin/pytest
.venv/bin/uvicorn nebula_api.main:app --reload --port 8000
```

On Windows, replace `.venv/bin/` with `.venv\\Scripts\\`.

Probe endpoints are `GET /healthz` and `GET /readyz`. They intentionally return no
environment values, dependency addresses, credentials, or host details.
