# Releasing the client

How a Nebula client release is cut, as practised since 0.1.12, with a SHA-256
manifest from the first release after 2026-10-01 (roadmap section 60).

Releases are built on GitHub from the release tag, unsigned and with build
attestations; the maintainer checks them, signs the APKs and the manifest on
their own machine, where the signing key lives (see
[release-signing-key.md](release-signing-key.md)), and publishes. No signing
key is ever stored on GitHub.

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

## 2. Build (GitHub)

Tag the merged release commit and push the tag:

```sh
git tag vX <merge commit> && git push origin vX
```

The **Release** workflow (`.github/workflows/release.yml`) then builds
everything from that tag on GitHub's machines, and refuses if the tag,
`pubspec.yaml` and `kClientVersion` disagree:

- **Android:** one APK per ABI and a universal one, all with the same
  version code (never `--split-per-abi`). There is no signing key on GitHub,
  so they come out signed with the public debug key and are named
  `nebula-vpn-vX-android-<abi>-tosign.apk`. **Never hand one of these out.**
- **Windows:** `nebula-vpn-vX-windows-x64-setup.exe` and
  `nebula-vpn-vX-windows-x64-portable.zip`.
- **Linux:** `nebula-vpn-vX-linux-x64.deb`, `.AppImage` and `.tar.gz`.
- **SBOM:** `nebula-vpn-vX-sbom.cdx.json`.

Each file gets a build attestation: GitHub's signed record of the commit and
workflow that produced it. When all are built, the workflow puts them in a
**draft** release vX. Nothing is public yet.

A pull request that changes the workflow runs it as a dry run: the same
builds, kept as workflow artifacts, with no draft and no attestations.

Public releases carry no addresses, so the workflow passes no defines. A
private build with a deployment's addresses (`API_BASE_URL`, `FREE_LINKS`)
is still made by hand on the maintainer's machine, as before, and never
published.

## 3. Check and sign (the maintainer's machine)

Download the draft's files into a folder of their own:

```sh
mkdir -p build/release-X && cd build/release-X
gh release download vX -R Parsabrg/vpn
```

**Check each came from the workflow and the tag.** This fails for a file
anyone swapped into the draft:

```sh
for f in nebula-vpn-vX-*; do gh attestation verify "$f" -R Parsabrg/vpn || echo "NOT VERIFIED: $f"; done
```

**Sign the APKs** with the release key
([release-signing-key.md](release-signing-key.md)). `apksigner` replaces the
debug signature; the files are already aligned:

```sh
KS=../../android/app/nebula-release.jks
for abi in arm64 arm x64 universal; do
  apksigner sign --ks "$KS" --ks-key-alias nebula \
    --out nebula-vpn-vX-android-$abi.apk nebula-vpn-vX-android-$abi-tosign.apk
  apksigner verify --print-certs nebula-vpn-vX-android-$abi.apk | grep SHA-256
done
rm nebula-vpn-vX-android-*-tosign.apk
```

Every SHA-256 printed must be the one in release-signing-key.md.

**The manifest**, over the final files, and its signature:

```sh
sha256sum nebula-vpn-vX-* > SHA256SUMS.txt
sha256sum -c SHA256SUMS.txt
ssh-keygen -Y sign -f ../../android/app/nebula-release-sign -n nebula-release SHA256SUMS.txt
ssh-keygen -Y verify -f ../../../../docs/release-signers -I releases@nebula-vpn \
  -n nebula-release -s SHA256SUMS.txt.sig < SHA256SUMS.txt
```

Anyone can then check a download with `sha256sum -c SHA256SUMS.txt
--ignore-missing` (Linux, Git Bash) or `Get-FileHash <file> -Algorithm
SHA256` (Windows), and the manifest's signature with the second
`ssh-keygen` command against `docs/release-signers` (OpenSSH 8.1 or newer).
The attestations are a second, independent check of the Windows and Linux
files: `gh attestation verify <file> -R Parsabrg/vpn`.

## 4. Publish

Replace the `-tosign` APKs in the draft with the signed ones, add the
manifest and its signature, write the notes, then publish as a pre-release:

```sh
for abi in arm64 arm x64 universal; do gh release delete-asset vX nebula-vpn-vX-android-$abi-tosign.apk -R Parsabrg/vpn -y; done
gh release upload vX nebula-vpn-vX-android-*.apk SHA256SUMS.txt SHA256SUMS.txt.sig -R Parsabrg/vpn --clobber
gh release edit vX --notes-file notes.md -R Parsabrg/vpn
gh release edit vX --draft=false --prerelease -R Parsabrg/vpn
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
