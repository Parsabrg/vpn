# Project progress

Last updated: 2026-07-18

## Current phase

Phase 0 — repository assessment, architecture, threat model, and delivery plan.

## Completed

- Read and normalized the Phase 1 requirements.
- Inspected `Parsabrg/vpn` through the connected GitHub application.
- Confirmed the repository is public, empty, and has `main` configured as its
  default branch.
- Defined the proposed monorepo boundaries and one-VPS deployment topology.
- Defined the security boundaries for the public API, administrator dashboard,
  worker, database, Redis, VPN agent, WireGuard host, and clients.
- Created an initial threat model and secret-handling contract.
- Listed environment variables and external decisions required before deployment.
- Created a milestone-based Phase 1 implementation and validation plan.

## Blocked

- Publishing is blocked because the GitHub App is not installed for, or has not
  been granted write access to, `Parsabrg/vpn`. A create-file attempt returned
  `403 Resource not accessible by integration`.
- Domain name, administrator email, production email provider, VPS details, and
  backup destination have not been supplied.
- Android and Windows tunnel verification requires real target devices or VMs.

## Pending

- Grant the connected GitHub App access to `Parsabrg/vpn`.
- Publish these Phase 0 files on `agent/phase-0-architecture` and open a draft PR.
- Obtain decisions listed in `docs/decisions-needed.md`.
- Begin Phase 1.1 repository and CI scaffold only after Phase 0 review.

## Decisions recorded

- WireGuard is the only Phase 1 VPN protocol.
- FastAPI remains unprivileged and cannot execute arbitrary host commands.
- A separate host-side VPN agent owns WireGuard mutations.
- Client private keys are generated and retained on the client device.
- API-to-agent communication uses mutual TLS and a versioned, allowlisted API.
- Access JWTs are short lived; refresh and one-time tokens are random, rotated,
  hashed at rest, and revocable.
- Administrator sessions use secure HttpOnly cookies, CSRF protection, and TOTP
  MFA with hashed recovery codes.
- Email is delivered through a durable database outbox plus a Redis-backed worker.
- SMTP and Resend are the initial email provider implementations.
- Redis uses AOF persistence (`appendfsync everysec`) in production because it
  carries sessions, rate limits, and background jobs; PostgreSQL remains the
  source of truth.

## Known limitations

- This phase contains plans and contracts, not runnable application code.
- No claims are made yet about VPN connectivity, leak protection, kill switches,
  native integrations, deployment, backups, or end-to-end security.
