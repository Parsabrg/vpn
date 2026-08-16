# Nebula worker

Polls the `email_deliveries` outbox table and delivers queued account-request,
activation, and password-reset email through SMTP or Resend.

It intentionally does not import `nebula_api`: it talks to PostgreSQL and
Redis directly through the same table/key conventions the API writes, kept in
sync by convention rather than shared code (see `src/nebula_worker/outbox.py`
and `nebula_api.accounts.email_outbox` in `services/api`).

## Local development

```bash
pip install -e ".[dev]"
ruff check .
mypy
pytest
python -m nebula_worker.main
```

Configuration is loaded from `NEBULA_*` environment variables; see
`.env.example` at the repository root for the full list.
