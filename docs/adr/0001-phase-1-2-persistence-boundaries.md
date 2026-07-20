# ADR 0001: Phase 1.2 persistence boundaries

- Status: accepted
- Date: 2026-07-20

## Context

Phase 1.2 introduces the first durable schema. Authentication, approval workflows,
administrator CRUD, and VPN provisioning behavior are delivered by later milestones,
but their tables must preserve the protocol-neutral architecture from the start.

## Decision

- PostgreSQL is the only supported persistence engine. Runtime access uses
  SQLAlchemy 2's async `psycopg` dialect; Alembic owns explicit migrations.
- Application startup never runs migrations. Deployment and development use a
  separate migration command and, in production, a separate database role.
- The migration defines the architecture's identity, approval, token, protocol,
  topology, provisioning-intent, audit, email, health, and settings records. This
  phase exposes no business HTTP endpoints; only `/healthz` and `/readyz` remain.
- API/domain identifiers are application-generated UUIDv4 values. They are opaque
  references, never credentials.
- Original email values are retained for display. Uniqueness uses the syntactically
  validated, IDNA-normalized value case-folded in full. Provider-specific plus-tag
  or dot rewriting is forbidden.
- Canonical usernames are optional ASCII identifiers of 3–32 characters. They are
  lower-cased and kept separate from future Unicode display names.
- User and administrator email namespaces are intentionally separate. A matching
  email never implies a role or authentication realm.
- Password, activation, reset, refresh, and idempotency secrets are never stored in
  plaintext. Token records hold fixed-length keyed digests plus key-version and
  lifecycle metadata.
- The interactive initial-administrator command brings forward only the Argon2id
  password-hashing primitive needed to avoid placeholder credentials. Login,
  password verification policy, MFA, sessions, and recovery remain Phase 1.3 work.
- Protocol profiles contain closed, reviewed metadata only. They cannot contain raw
  Xray JSON, shell text, executable paths, templates, or private key material. Xray
  profiles remain disabled and cannot be provisioned in Phase 1.2.
- Client WireGuard private keys never enter PostgreSQL. Xray credential storage, if
  later used, requires a complete envelope-encryption tuple whose wrapping key lives
  outside the database.
- Foreign-key delete behavior is explicit and restrictive for business records.
  Audit rows are append-oriented and never contain request bodies or model snapshots.

## Consequences

- PostgreSQL integration and migration tests are required; SQLite is not treated as
  a substitute for constraint behavior.
- Schema changes require new immutable Alembic revisions after this phase merges.
- Cross-row and cross-table rules such as device quotas, capability intersection,
  address-pool containment, and lifecycle transitions require locked domain-service
  transactions in their owning milestones in addition to database constraints.
- Phase 1.2 can validate storage and migration safety without creating an
  unauthenticated mutation surface.
