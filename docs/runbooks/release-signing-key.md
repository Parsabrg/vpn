# The release signing key

Android identifies an app by the key it was signed with, not by its package
name. If this key is lost, no further update can ever be installed over an
existing Nebula install: every user has to uninstall first, losing their local
state, and has to be persuaded to do so through a channel that is not the app.
There is no recovery, no appeal, and no reissue.

It lives in `apps/mobile/android/app/` on the maintainer's laptop, correctly
gitignored — a signing key must never be committed. Since 2026-09-17 an
encrypted copy also travels in every nightly backup; see "Where it is backed
up" below.

## What has to be backed up

Both files, together. Either alone is useless.

| File | What it is |
|---|---|
| `apps/mobile/android/app/nebula-release.jks` | the key itself |
| `apps/mobile/android/key.properties` | the two passwords, the alias, the filename |

## Identity of the current key

Recorded here so a restored copy can be checked before anyone trusts it. None
of this is secret — the certificate ships inside every APK.

```
Alias    nebula
Owner    CN=Nebula VPN, OU=Nebula, O=Nebula, L=Unknown, ST=Unknown, C=US
Valid    2026-09-01 to 2056-08-24
SHA-256  4F:14:93:A2:38:77:0C:59:F3:08:82:DB:4B:01:72:BE:
         DA:E7:2E:81:51:25:28:C5:8B:D9:BA:37:55:36:4A:59
```

Verify a restored keystore matches:

```
keytool -list -v -keystore nebula-release.jks -alias nebula
```

If the SHA-256 differs, it is a different key and will not update the installed
app.

## Where it is backed up

Both files, tarred and encrypted on the laptop to the backup `age` recipient,
are at `/etc/nebula/secrets/release-signing-key.tar.gz.age` on the VPS. The
nightly backup copies that whole directory, so every backup in B2 carries it,
and the bucket's 30-day lifecycle rule never leaves it without a copy as long
as backups keep running.

This is the placement the section below allows: the VPS holds only
ciphertext, and only the offline `age` identity — kept by the operator, never on
the server — can open it. Someone who takes the VPS gets nothing they can sign
with.

It was encrypted without the plaintext leaving the laptop:

```bash
R=age1...   # NEBULA_BACKUP_AGE_RECIPIENT from /etc/nebula/backup.env; public
docker run --rm -e R="$R"   -v "$PWD/apps/mobile/android/app/nebula-release.jks:/in/app/nebula-release.jks:ro"   -v "$PWD/apps/mobile/android/key.properties:/in/key.properties:ro"   -v "$PWD/out:/out" debian:bookworm-slim sh -c   'apt-get update && apt-get install -y age &&
   tar -czf - -C /in key.properties app/nebula-release.jks |
   age -r "$R" -o /out/release-signing-key.tar.gz.age'
```

Then copied to the VPS and installed `640 root:nebula-secrets`, like its
neighbours. Redo both steps if the keystore or its passwords ever change.

### Restoring it

1. Restore a backup as in `infrastructure/backup/README.md` until you have the
   decrypted archive, then take `secrets/release-signing-key.tar.gz.age` out of
   it. Or copy the file straight from the VPS, if the VPS is still there.
2. Decrypt it with the same offline identity, on a machine you trust:

   ```bash
   age -d -i backup-identity.txt release-signing-key.tar.gz.age | tar -xzf -
   ```

   That gives `key.properties` and `app/nebula-release.jks`; put them back
   under `apps/mobile/android/`.
3. Check the fingerprint against the one recorded above before trusting it.

Tested end to end 2026-10-30, after the backup identity of 2026-09 was found
lost: a new identity was made, both files were encrypted to it again (the
keystore's SHA-256 and the manifest key's fingerprint checked after
decrypting), `NEBULA_BACKUP_AGE_RECIPIENT` was changed to it, and that day's
server backup decrypted on the laptop with the database dump and both files
in it. Backups made before then are encrypted to the lost identity and
cannot be opened. Repeat at the quarterly restore test, and keep the
identity in two offline places: losing it loses every backup.

## Other places

A password manager holding both files as attachments is also fine, and gives a
copy that does not depend on the backups. Two placements to avoid:

- **The VPS, unencrypted.** It is the most exposed machine in this project.
  Someone who compromises it could sign a malicious update to an app whose users
  route all their traffic through it — strictly worse than losing the key.
- **The B2 bucket, unencrypted.** It is not a place to drop a bare `.jks`.

## The manifest signing key

A second, separate key signs each release's `SHA256SUMS.txt` (roadmap
section 61), so a download can be traced to whoever holds it rather than
only matched against a list anyone could have rewritten. OpenSSH's own
file signing (`ssh-keygen -Y sign`, namespace `nebula-release`): nothing to
install on Windows 10+, Linux or macOS. Created 2026-10-14.

| File | Where | Committed |
|---|---|---|
| private key | `apps/mobile/android/app/nebula-release-sign` (no passphrase, like the release builds' other keys) | never -- gitignored |
| public key | `docs/release-signers`, as OpenSSH's allowed-signers line | yes |

```
ED25519  SHA256:gu56x3w7gUsczR/KJx8GQKkEEavWUTNeCAeA6TVJZZc  Nebula VPN releases
```

Backed up like the Android key: encrypted on the laptop to the backup `age`
recipient and installed `640 root:nebula-secrets` as
`/etc/nebula/secrets/release-manifest-key.tar.gz.age` (2026-10-14), so the
nightly backups carry it. The procedure above, with this one file:

```bash
docker run --rm -e R="$R" \
  -v "$PWD/apps/mobile/android/app/nebula-release-sign:/in/nebula-release-sign:ro" \
  -v "$PWD/out:/out" debian:bookworm-slim sh -c \
  'apt-get update && apt-get install -y age &&
   tar -czf - -C /in nebula-release-sign |
   age -r "$R" -o /out/release-manifest-key.tar.gz.age'
```

Losing it is not fatal, unlike the Android key: make a new one, add its line
to `docs/release-signers` and keep the old line, so earlier releases still
verify. If it leaks, replace its line with a `@revoked` entry
(`man ssh-keygen`, ALLOWED SIGNERS) and sign from the new key.

## If it is already lost

Nothing here recovers it. The next release is signed with a new key, gets a
different package identity, and every existing install must be removed by hand
before the replacement will install. Say so plainly in the release notes rather
than letting people discover it as a failed update.
