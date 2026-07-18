# Nebula VPN

Nebula VPN is a secure, approval-based multi-protocol VPN platform. The final
product combines native WireGuard with Xray-core profiles selected by the user.
Phase 1 delivers the secure control plane and WireGuard path first while keeping
the data model, agent API, and clients ready for phased Xray support.

## Current status

The repository is in **Phase 0: architecture and security planning**. No VPN,
authentication, dashboard, or client functionality is implemented yet. See
[`PROJECT_PROGRESS.md`](PROJECT_PROGRESS.md) for the exact status.

## Design principles

- No unrestricted public registration.
- Users choose their password through a single-use activation link.
- Client WireGuard private keys never leave the device.
- Xray credentials are unique per device/profile and never exposed through public
  subscription URLs, logs, analytics, or error reports.
- Users can select only protocol profiles enabled for their account and server.
- The public API never receives root or unrestricted shell access.
- VPN mutations are performed by narrow WireGuard and Xray drivers behind a
  mutually authenticated agent.
- Sensitive values belong in secret files or a secret manager, never Git.
- Phase 1 targets one Ubuntu VPS without coupling the data model to one server.

## Planned monorepo

```text
apps/
  admin/                 Next.js administrator dashboard
  mobile/                Flutter Android and Windows client
services/
  api/                   FastAPI control plane and worker
  vpn-agent/             Hardened WireGuard and Xray management agent
infrastructure/
  compose/               Development and production Compose files
  nginx/                 Reverse proxy and TLS configuration
  systemd/               VPN agent service units
  backup/                Backup and restore tooling
docs/                     Architecture, threat model, operations, and plans
.github/workflows/        CI and security automation
```

## Phase 0 documents

- [Repository assessment](docs/repository-assessment.md)
- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Environment variables](docs/environment.md)
- [Phase 1 plan](docs/phase-1-plan.md)
- [WireGuard and Xray protocol roadmap](docs/protocol-roadmap.md)
- [Decisions and credentials needed](docs/decisions-needed.md)

## Local configuration

Copy `.env.example` only for local development and replace placeholders outside
Git. Production secrets will be mounted as files or supplied by a secret manager.
Do not commit `.env`, private keys, certificates, WireGuard configurations, Xray
profiles, subscription links, or database backups.
