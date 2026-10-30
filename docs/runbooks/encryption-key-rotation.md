# Rotating an encryption key

Four secrets encrypt or sign something that is stored and read back later. All
four can be replaced, and replacing any of them carelessly destroys data with
no error at the time.

That is not hypothetical. On 30 August 2026 the Xray encryption key was
regenerated during setup, reusing version `1`, with no previous-keys directory
configured:

| | |
| --- | --- |
| 20:08:29 – 20:28:31 | 14 credentials written under the first key |
| **20:45:39** | `/etc/nebula/secrets/xray_encryption_key` created |
| 20:48:36 onward | every later credential written under the second key |

Those 14 credentials are permanently unreadable. Nothing failed at the time,
nothing recorded that a key had changed, and establishing the cause weeks
later took a byte-level audit and a file birth timestamp. Had a previous-keys
directory existed, the old key would have moved into it and nothing would have
been lost.

## How rotation is supposed to work

Every encrypted row records the **version number** of the key that encrypted
it. It is never re-encrypted afterwards. So the old key must remain available
for as long as any row still names its version.

That is what the previous-keys directory is for. The loader builds a ring:
every file in that directory, plus the current key.

- One file per retired key. **The filename is that key's old version number**,
  in decimal -- a retired version 1 is a file named exactly `1`.
- Each file is **exactly 32 raw bytes**, not hex, not base64.
- The directory must contain only files, and must not contain a file named
  with the *current* version.

Rotation is therefore three things that must happen together: a new key file,
the old key moved into the previous-keys directory under its old number, and
the version number incremented. Do the first and third without the second and
every existing row becomes unreadable.

## What each key protects

| Key | Protects | If the old key is lost |
| --- | --- | --- |
| `xray_encryption_key` | Every device's VPN credential | Those devices cannot be served or revoked; their traffic cannot be attributed |
| `mfa_encryption_key` | Admin TOTP seeds | Every admin loses their second factor and cannot sign in |
| `token_pepper` | Refresh, reset, activation and account-request tokens | Every outstanding token of those kinds is invalidated |
| JWT keypair | Access-token signatures | Issued access tokens stop verifying until they expire |

The MFA key is the most dangerous of the four. There is no re-encryption
sweep: an admin's seed stays under its original version until they re-enrol,
which may be never.

## Two traps specific to this host

**The secrets directory is mounted read-only into the containers.** Generating
a key with `nebula-api generate-symmetric-key --out /etc/nebula/secrets/...`
fails -- the path is not writable from inside. Create the key on the host.

**The container reads secrets through a group, not as root.** The API runs as
`uid=10001(nebula)` with supplementary group `9443`, which is
`nebula-secrets` on the host. A key file created with default root-only
permissions is unreadable to it, and the API will not start. Every file in
`/etc/nebula/secrets` is `root:nebula-secrets` mode `640`; a new one must
match.

## Rotating the Xray encryption key

Back up first -- `systemctl start nebula-backup.service`. Nothing here edits
the database, but the recovery path if a step is missed is a restore.

1. **Create the previous-keys directory**, if this is the first rotation.

   ```bash
   install -d -o root -g nebula-secrets -m 750 /etc/nebula/secrets/xray_previous_keys
   ```

2. **Move the current key into it, named by its current version.** Read the
   version you are retiring from `/etc/nebula/compose.env`
   (`NEBULA_XRAY_KEY_VERSION`) -- do not assume it is 1.

   ```bash
   mv /etc/nebula/secrets/xray_encryption_key \
      /etc/nebula/secrets/xray_previous_keys/1
   ```

   This is the step whose omission caused the August loss. Do it before
   generating the replacement, so there is no moment where the only copy of
   the old key can be overwritten.

3. **Generate the new key** -- exactly 32 raw bytes, with the same ownership
   and mode as its siblings.

   ```bash
   openssl rand 32 > /etc/nebula/secrets/xray_encryption_key
   chown root:nebula-secrets /etc/nebula/secrets/xray_encryption_key
   chmod 640 /etc/nebula/secrets/xray_encryption_key
   ```

4. **Point the compose file at the directory.** `NEBULA_XRAY_PREVIOUS_ENCRYPTION_KEYS_DIR`
   is deliberately absent from `infrastructure/compose/production.yaml`,
   because the loader requires a non-empty setting to name a directory that
   exists, and a fresh deploy has none. Add it under both `api` and `worker`:

   ```yaml
   NEBULA_XRAY_PREVIOUS_ENCRYPTION_KEYS_DIR: /etc/nebula/secrets/xray_previous_keys
   ```

5. **Increment the version** in `/etc/nebula/compose.env`:

   ```
   NEBULA_XRAY_KEY_VERSION=2
   ```

6. **Recreate the services that read it.**

   ```bash
   cd /opt/nebula/infrastructure/compose
   docker compose -p nebula-production --env-file /etc/nebula/compose.env \
     -f production.yaml up -d --force-recreate --no-deps api worker usage
   ```

7. **Verify before walking away** -- see below.

## The configuration refuses to start rather than losing data quietly

Several ways of getting this wrong are caught at startup, and the API exits
with `authentication key material is invalid` rather than running:

- a previous-keys file named with the *current* version (you moved the old key
  but forgot to increment)
- a filename that is not a decimal number
- a file that is not exactly 32 bytes
- the directory named by the setting not existing, or containing anything that
  is not a file

This is deliberate. A refusal to start is recoverable in a minute; silently
running with an incomplete ring is what loses credentials.

The one mistake it cannot catch is the August one: replacing the key file
in place while leaving the version alone. Nothing is inconsistent, and the
system has no way to know the bytes changed.

## Verifying

```bash
docker exec nebula-production-api-1 nebula-api audit-credential-keys
```

It tries every held key against every credential. After a correct rotation
everything still opens, and the report names both keys:

```
Readable:            170
Unreadable:          0
Key version 1 wrote credentials under: <digest of the retired key>
Key version 2 wrote credentials under: <digest of the new key>
```

Two different digests under two different versions is what a healthy
rotation looks like. Two digests under the *same* version is the August
failure, and the report says so in as many words.

Any non-zero `Unreadable` means the old key is not in the ring. Stop and put
it back before provisioning anything else -- the number only grows.

Also confirm the API is actually serving:

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://api.example.org:8444/readyz   # 200
```

## When the retired key can be deleted

Not on a schedule. For the Xray key, only once no row still names its version:

```bash
docker exec nebula-production-postgres-1 psql -U postgres -d nebula -c \
  "select key_version, count(*) from device_protocol_credentials
    where ciphertext is not null group by key_version"
```

A count against version 1 means version 1's key is still load-bearing.

`docs/environment.md` has the equivalent windows for the other three: 24 hours
for a retired JWT public key, the longest opaque-token TTL for a pepper, and
for MFA the same rule as here -- only after a query shows zero
`admin_totp_credentials` rows reference that version.

## If it has already gone wrong

If the old key is genuinely gone, the plaintext is gone with it. There is no
recovery, and no amount of the current key will help.

What can be done is stop the loss being re-reported forever, so the next
genuine failure is visible:

```bash
docker exec nebula-production-api-1 nebula-api audit-credential-keys --mark-lost
```

That records `key_material_lost_at` on every credential no held key can open.
It is a conclusion, not a repair. Affected devices must be revoked and
re-provisioned to work again -- a credential that cannot be decrypted cannot
be served *or* revoked cleanly.
