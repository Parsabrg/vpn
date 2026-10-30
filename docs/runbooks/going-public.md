# Going public

Published 2026-10-30 as a fresh repository with one initial commit. The
development history (pull requests, releases up to 0.1.32) stays in a
private archive: GitHub keeps every pull request's commits under
`refs/pull/*`, which no push can rewrite, and that history named the
production domain and server.

Checked before publishing:

- **Secrets:** gitleaks over every commit of the old history, with this
  repository's rules and with its defaults: none.
- **Deployment details:** the production domain, server addresses and the
  operator's name in docs and test fixtures replaced with `example.org`,
  `203.0.113.10` and `owner`.
- **Release signing:** the keys were never in the repository; see
  `release-signing-key.md`.

## Why the name stayed `Parsabrg/vpn`

Installed apps check for updates at
`api.github.com/repos/Parsabrg/vpn/releases/latest`
(`apps/mobile/lib/core/updates/update_check.dart`). Releases are published
here from 0.1.33 on, so every installed app finds them.

## CI

Every job runs on GitHub-hosted runners, free for a public repository. None
runs on the project's own servers: a pull request from a fork is anyone's
code. Settings → Actions → General → "Require approval for all external
contributors" is on, and `main` requires the checks to pass.
