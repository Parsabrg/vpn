# Project progress

Last updated: 2026-07-18

## Current phase

Phase 1.1 — monorepo and CI scaffold. Phase 0 was accepted and squash-merged in
pull request #1.

## Completed

- Defined and merged the multi-protocol architecture, threat model, environment
  contract, and delivery roadmap.
- Created independent FastAPI control-plane and VPN-agent packages with immutable,
  validated settings and non-sensitive health/readiness probes.
- Kept the API unprivileged and restricted the agent scaffold to two probe routes;
  it accepts no shell text, protocol configuration, or provisioning operation.
- Added non-root Python container images and an accessible, responsive Next.js
  administration shell that explicitly labels unimplemented capabilities.
- Added a Flutter 3.44 shared client shell and widget test without claiming native
  tunnel support.
- Added a loopback-only development Compose stack with PostgreSQL, persistent Redis,
  Mailpit, isolated networks, health gates, read-only application containers, and
  a capability-free mock agent.
- Added minimal-permission CI for Python, Next.js, Flutter, Compose smoke testing,
  dependency review, secret scanning, and container vulnerability scanning.
- Added exact tool/direct-dependency pins, an npm lockfile, Dependabot, root task
  commands, and a development guide.

## Validation recorded locally

- API: Ruff, format, strict mypy, 13 pytest tests, and 100% branch coverage pass.
- VPN agent: Ruff, format, strict mypy, 7 pytest tests, and 96% branch coverage pass.
- Admin: Prettier, ESLint, strict TypeScript, 5 Vitest tests, production build, and
  production dependency audit pass.
- Compose configuration renders successfully.
- GitHub Action references use full commit SHAs.

The local machine did not have Flutter or a running Docker daemon. Flutter analysis,
widget tests, image builds, and the container health smoke test therefore remain CI
gates rather than locally verified claims.

## External inputs pending

- Repository visibility and source license.
- Minimum supported Android and Windows versions.
- Domain, administrator email, production email provider, VPS details, capacity,
  network ranges, and backup destination.
- Android and Windows tunnel verification devices or VMs.

## Next milestone

- Review the Phase 1.1 scaffold and its CI results.
- Generate Android and Windows host projects after support versions are confirmed.
- Begin Phase 1.2 database and protocol-neutral identity/topology models in a
  separate pull request.

## Known limitations

- No authentication, account approval, email delivery, database schema, VPN
  provisioning, WireGuard, Xray, native tunnel integration, backup, or production
  deployment exists yet.
- Health probes demonstrate process state only; they are not proof of VPN or
  dependency readiness.
- Python and Flutter direct dependencies are pinned, but their complete transitive
  graphs are not yet committed as platform-independent lock data.
- Kill switch, DNS/IPv6 leak protection, and target-platform behavior remain
  unimplemented and unverified.
