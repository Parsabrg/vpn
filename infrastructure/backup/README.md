# Off-host encrypted backups

**`install.sh` does this since 2026-10-30.** It asks where backups also go
(Backblaze B2, or "this server only" with a warning) and installs the AWS CLI
for B2. It shows a new backup key once and deletes it from the server after
you confirm it is saved; encrypting needs only the public half in
`/etc/nebula/backup.env`. `--restore` uses the key you type and never stores
it. The manual steps below are for installs from before then.

> **`install.sh` sets this up:** the daily timer, encrypted copies kept 14 days
> in `/var/backups/nebula`, and the B2 upload when chosen (above). Each backup
> holds the database, the secrets, the `nebula-state` volume and
> `/etc/nebula`'s configuration, and `sudo ./install.sh --restore <file>`
> rebuilds a server from one (tested 2026-10-26: a wiped server came back with
> the same identity, keys and data).

Daily backup of the Postgres database and `/etc/nebula/secrets`
(everything needed to reconstitute this deployment from nothing), archived,
encrypted with [`age`](https://github.com/FiloSottile/age) to the operator's
public key, and uploaded to a Backblaze B2 bucket over its S3-compatible API.
Decided: Backblaze B2, daily snapshots
with 30-day retention, operator-held `age` key, quarterly restore tests.

`backup.sh` never decrypts anything -- restore is a separate, deliberately
unscripted, manual procedure below, so a compromised backup script can't
also compromise a restore.

## One-time setup

1. **Install `age` and `awscli` on the VPS** (not containerized -- this runs
   directly on the host, alongside the agent's own bare-metal deploy):
   ```shell
   sudo apt-get update && sudo apt-get install -y age awscli
   ```

2. **Create the B2 bucket and application key**, in the Backblaze dashboard
   (this needs your own B2 account -- not something this session can do for
   you):
   - Create a private bucket (e.g. `nebula-vpn-backups`).
   - Note the bucket's **S3-compatible endpoint** shown on the bucket page
     (e.g. `https://s3.us-west-004.backblazeb2.com` -- varies by region).
   - Create an **application key** scoped to just this bucket (Account →
     Application Keys → Add a New Application Key). Note the key ID and the
     application key itself -- the application key is only ever shown once.
   - Add a **lifecycle rule** on the bucket (Bucket Settings → Lifecycle
     Settings) to delete files older than 30 days, matching the retention
     decision -- simpler than scripting pruning here.

3. **Generate the `age` keypair**, on the VPS, and immediately move the
   private half somewhere that isn't this server:
   ```shell
   age-keygen -o /tmp/nebula-backup-key.txt
   cat /tmp/nebula-backup-key.txt
   ```
   Copy the `AGE-SECRET-KEY-...` line into your password manager as a secure
   note, and the `# public key: age1...` comment line somewhere you can
   paste from for step 4. Then:
   ```shell
   shred -u /tmp/nebula-backup-key.txt
   ```
   The private key must never live on this VPS -- losing it makes every
   backup permanently unrecoverable, and it isn't needed here since this
   script only ever encrypts, never decrypts.

4. **Store the B2 credentials as secret files** (mode `0600`, owned
   `root:root` -- these are host-only, no container needs them, unlike
   `/etc/nebula/secrets`'s `nebula-secrets` group convention):
   ```shell
   install -d -o root -g root -m 0700 /etc/nebula/backup-secrets
   printf '%s' '<the B2 application key id>' > /etc/nebula/backup-secrets/b2_access_key_id
   printf '%s' '<the B2 application key>' > /etc/nebula/backup-secrets/b2_application_key
   chmod 0600 /etc/nebula/backup-secrets/*
   ```

5. **Write `/etc/nebula/backup.env`** (mode `0640`, owned `root:root`):
   ```
   NEBULA_BACKUP_B2_BUCKET=nebula-vpn-backups
   NEBULA_BACKUP_B2_ENDPOINT=https://s3.us-west-004.backblazeb2.com
   NEBULA_BACKUP_AGE_RECIPIENT=age1...   # the public key from step 3, not a secret
   NEBULA_BACKUP_B2_KEY_ID_FILE=/etc/nebula/backup-secrets/b2_access_key_id
   NEBULA_BACKUP_B2_APPLICATION_KEY_FILE=/etc/nebula/backup-secrets/b2_application_key
   ```

6. **Install and enable the timer**:
   ```shell
   cp infrastructure/systemd/nebula-backup.service infrastructure/systemd/nebula-backup.timer /etc/systemd/system/
   chmod +x infrastructure/backup/backup.sh
   systemctl daemon-reload
   systemctl enable --now nebula-backup.timer
   ```
   Run it once by hand to confirm it works before trusting the timer:
   ```shell
   systemctl start nebula-backup.service
   journalctl -u nebula-backup.service -n 50 --no-pager
   ```

## Restore procedure

Deliberately manual, not scripted. Do this for real every quarter (the
decided restore-test cadence), ideally against a throwaway VPS or a local
Postgres instance, not the production database.

1. Download the encrypted backup from B2 (via the dashboard, or
   `aws s3 cp --endpoint-url <endpoint> s3://<bucket>/<file> .`).
2. Decrypt it with the `age` private key from your password manager:
   ```shell
   age --decrypt -i <(echo "AGE-SECRET-KEY-...") -o backup.tar.gz nebula-backup-<timestamp>.tar.gz.age
   tar -xzf backup.tar.gz
   ```
   This produces `postgres/postgres.sql` and a `secrets/` directory mirroring
   `/etc/nebula/secrets`.
3. Restore the secrets directory to `/etc/nebula/secrets` on the target host
   (matching ownership/permissions in `../compose/README.md`).
4. Restore the database into a fresh Postgres instance:
   ```shell
   psql -U postgres -d <database> < postgres/postgres.sql
   ```
5. Bring the stack up (`systemctl start nebula-compose`) and confirm the
   admin dashboard loads, an admin can sign in, and `GET /v1/admin/vpn-servers/health`
   shows the expected servers -- that's the actual proof a restore worked,
   not just that the commands ran without error.
6. Securely delete the decrypted files (`shred -u backup.tar.gz
   postgres/postgres.sql`, `rm -rf secrets/`) once you're done verifying.
