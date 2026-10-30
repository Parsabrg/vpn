# Releasing the client

How a Nebula client release is cut, as practised since 0.1.12, with a SHA-256
manifest from the first release after 2026-10-01 (roadmap section 60).

Releases are built on the maintainer's machine: the Android signing key lives
there (see [release-signing-key.md](release-signing-key.md)), and the hosted
CI has no budget.

**Public releases carry no addresses.** No `API_BASE_URL`, no
`API_BACKUP_URL`, no `FREE_LINKS`: one generic app for every installation,
connected on first launch with the address or pairing link its operator
gives (the app then learns the deployment's other routes from `/v1/routes`).
A build with a deployment's addresses compiled in is a private build for
that deployment only, never a published release.

0.1.31 is the one exception, and the last: it still carries the owner
deployment's address and keeps it as the phone's pairing on first launch
(`pairing_providers.dart`), so the generic 0.1.32 that follows does not send
every existing user back to the pairing screen. Build it without the
Vercel front, which is gone (`API_BACKUP_URL=<cdn url>` only).

## 1. Version

A pull request named "Release X" changes exactly two things:

- `apps/mobile/pubspec.yaml`: `version: X+N`, N one more than the last.
- `apps/mobile/lib/core/app_info.dart`: `kClientVersion = 'X'`.

Run the local Flutter gate (`dart format --set-exit-if-changed lib test`,
`flutter analyze --fatal-infos`, `flutter test`), then merge once the runner
checks pass.

## 2. Build

From `apps/mobile` on the merged `main`, into a folder of its own under
`build/` -- never `dist/`, which may hold a copy someone is running.

```sh
DEFINES=""   # public releases from 0.1.32; 0.1.31 only: see above
```

`--dart-define-from-file=<free.json>` with `{"FREE_LINKS": "vless://..."}`
gives a private build relays to offer someone with no server. Public
releases leave it out: free mode then uses the links and subscriptions the
person adds.

- **Android**: one APK per ABI and a universal one, all with the same
  version code (`--target-platform android-arm64`, `android-arm`,
  `android-x64`, then none). Not `--split-per-abi`, which gives each ABI
  its own version code. Check every APK is signed by the release key:
  `apksigner verify --print-certs` must show the SHA-256 in
  release-signing-key.md.
- **Windows**: `tool/build_windows_installer.ps1 -ApiBaseUrl <api url>
  -ApiBackupUrl <cdn url> -DefinesFile <free.json> -OutputDirectory
  build\release-X`; it makes the setup and the portable zip.
- **Linux** (on Linux or WSL): `OUTPUT_DIRECTORY=build/release-X
  tool/build_linux_packages.sh $DEFINES`; it makes the .deb, the AppImage
  and the portable .tar.gz.

Name the files `nebula-vpn-vX-<platform>-<arch>[-<kind>].<ext>`, as the
releases so far: `nebula-vpn-vX-android-arm64.apk`,
`nebula-vpn-vX-windows-x64-setup.exe`, `nebula-vpn-vX-linux-x64.deb`,
`nebula-vpn-vX-linux-x64.AppImage`, `nebula-vpn-vX-linux-x64.tar.gz`.

## 3. Manifest

In the release folder, once every file is final, first the SBOM -- every
Dart package, engine binary (with the digest the build pins) and server
package that went into this release, read from the files that pin them
(roadmap section 68) -- so the manifest covers it too:

```sh
python ../../tool/sbom.py --version X > nebula-vpn-vX-sbom.cdx.json
sha256sum nebula-vpn-vX-* > SHA256SUMS.txt
sha256sum -c SHA256SUMS.txt
```

`SHA256SUMS.txt` is uploaded with the files. Anyone can check a download
with `sha256sum -c SHA256SUMS.txt --ignore-missing` (Linux, Git Bash) or
`Get-FileHash <file> -Algorithm SHA256` (Windows). That proves a file is the
one in the manifest; the manifest's signature (roadmap section 61) proves
who wrote the manifest. Sign it with the release key
([release-signing-key.md](release-signing-key.md), "The manifest signing
key"):

```sh
ssh-keygen -Y sign -f ../../android/app/nebula-release-sign -n nebula-release SHA256SUMS.txt
ssh-keygen -Y verify -f ../../../../docs/release-signers -I releases@nebula-vpn \
  -n nebula-release -s SHA256SUMS.txt.sig < SHA256SUMS.txt
```

and upload `SHA256SUMS.txt.sig` with the rest. Anyone with OpenSSH 8.1 or
newer (Windows 10+, Linux, macOS) checks it against `docs/release-signers`
in this repository with the second command, then the files against the
manifest -- the release notes say how.

## 4. Publish

```sh
gh release create vX --draft --title "Nebula VPN X" --notes-file notes.md
gh release upload vX <files> SHA256SUMS.txt SHA256SUMS.txt.sig
gh release edit vX --draft=false --prerelease
```

Large uploads can drop through the Cloudflare route; upload the files one
at a time and repeat a failed one (`--clobber`).

Release notes say what changed for a person using the app, and how it was
tested. No links to the deployment, no tokens, no keys.

## 5. Promote

Test the pre-release on a real phone and on Windows before it becomes the
default download (0.1.5 was published untested and pulled). Then the owner
promotes it:

```sh
gh release edit vX --prerelease=false --latest
```

The app's update check reads the latest release, so promoting is what
offers it to everyone -- once the repository is public. Until then GitHub
answers "not found", and signed-in apps learn about it from the API
instead: set the version on the server and recreate the API container.

```sh
# on the VPS (zsh: write the compose command out in full)
sudo sed -i 's/^NEBULA_CLIENT_LATEST_VERSION=.*/NEBULA_CLIENT_LATEST_VERSION=X/' /etc/nebula/compose.env
grep -q '^NEBULA_CLIENT_LATEST_VERSION=' /etc/nebula/compose.env || echo 'NEBULA_CLIENT_LATEST_VERSION=X' | sudo tee -a /etc/nebula/compose.env
cd /opt/nebula/infrastructure/compose
docker compose -p nebula-production --env-file /etc/nebula/compose.env   -f production.yaml up -d --force-recreate --no-deps api
```
