# Contributing

Bug reports and pull requests are welcome. For a security problem, see
[SECURITY.md](SECURITY.md) instead.

## Before a pull request

- One change per pull request; keep it to what the change needs.
- Run the checks for each part you touched (`docs/development.md` has the setup):

  | Part | Checks |
  | --- | --- |
  | `services/*` | `ruff check`, `ruff format --check`, `mypy`, `pytest` (coverage at least 95%) |
  | `apps/admin` | `npm run check` |
  | `apps/mobile` | `dart format --set-exit-if-changed lib test`, `flutter analyze --fatal-infos`, `flutter test` |
  | shell scripts | `shellcheck` |

- `install.sh` must stay safe to run again on an installed server. When a
  default changes, servers that already have a value keep it.
- Update the docs the change affects in the same pull request (README,
  `docs/runbooks`, the status table in `docs/ROADMAP.md`).
- A big change (a new protocol, a new server role, a new platform): open an
  issue or write an ADR in `docs/adr/` first.

## Notes

- "archive #N" in the docs is a pull request in the private history this
  repository was published from; plain "#N" is one here.
- Never commit secrets, server addresses, or anything that identifies users.
  CI runs gitleaks on every pull request.
- Contributions are under the GPL-3.0 licence of this repository.
