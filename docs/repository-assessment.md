# Current repository assessment

Assessment date: 2026-07-18

Repository: `https://github.com/Parsabrg/vpn`

## Observed state

The GitHub API reports:

- Repository: `Parsabrg/vpn`
- Visibility: public
- Default branch: `main`
- Repository size: 0
- Existing branches: none returned
- Existing code, commits, CI, issues, and pull requests: none available to inspect
- Authenticated user: `Parsabrg`
- Reported repository permission: admin/push

The repository therefore has no existing work to preserve. It also has no initial
commit from which a feature branch can be created.

## Access discrepancy

Repository discovery succeeds, but a write through the connected GitHub App fails
with `403 Resource not accessible by integration`. Account-level repository
permission is not enough: the GitHub App installation must explicitly include this
repository and grant Contents and Pull requests write permissions.

## Safe bootstrap sequence

After access is granted:

1. Create the minimal initial commit on `main`.
2. Create `agent/phase-0-architecture` from that commit.
3. Commit only the reviewed Phase 0 files.
4. Open a draft pull request into `main`.
5. Require CI and review before merging.
6. Start implementation on a new feature branch after the Phase 0 PR merges.

Direct production deployment is out of scope until the owner supplies deployment
credentials and gives explicit permission.

## Proposed repository policies

Once the first commit exists, configure:

- Protect `main`; disallow direct pushes and force pushes.
- Require pull requests and at least one approving review.
- Require passing backend, admin, Flutter, secret-scan, and dependency checks.
- Require conversation resolution and branches to be current before merge.
- Enable Dependabot alerts and security updates.
- Enable GitHub secret scanning and push protection where the plan supports it.
- Prefer squash merging so each Phase 1 slice has a clear history.
- Use CODEOWNERS for security-sensitive agent, authentication, and infrastructure
  paths once collaborators exist.
