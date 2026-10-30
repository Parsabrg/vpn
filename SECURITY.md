# Security

## Reporting a vulnerability

Report it privately through GitHub: **Security → Report a vulnerability** on
this repository (private vulnerability reporting). Please do not open a public
issue, pull request or discussion for it.

Include what you found, how to reproduce it, and what an attacker gains. You
will get an answer within a week. Once a fix is released, the advisory is
published, crediting you unless you ask otherwise.

People use Nebula to get past censorship, so a weakness can put them at risk:
treat anything that identifies users, their traffic or the servers' addresses
as sensitive, and keep it in the private report.

## Scope

- The API, worker and VPN agent (`services/`), the admin panel (`apps/admin`),
  the apps (`apps/mobile`) and `install.sh`.
- Release signing: releases are signed with the key in `docs/release-signers`;
  a release whose `SHA256SUMS.txt.sig` does not verify is not ours.

Only the latest release is supported.

## What is already written down

`docs/threat-model.md` and `docs/runbooks/production-readiness-audit.md`
describe the known risks and what was done about each.
