[CmdletBinding()]
param(
    # Optional. Without it the build is generic: it is paired with a
    # deployment on first launch. With it, the build carries that one
    # deployment's address, as every build did before pairing.
    [string]$ApiBaseUrl,

    # The Cloudflare-proxied address the app falls back to when $ApiBaseUrl
    # cannot be reached at all. Omitting it builds an app with no way through
    # a blocked address. See infrastructure/nginx/README.md.
    [string]$ApiBackupUrl,

    # A JSON file of further build-time values, for --dart-define-from-file.
    # Where FREE_LINKS goes: a link's "&" ends the command when it is passed
    # on flutter.bat's own command line.
    [string]$DefinesFile,

    [string]$OutputDirectory = "dist",

    [switch]$Offline
)

$ErrorActionPreference = "Stop"

if ($ApiBaseUrl -and $ApiBaseUrl -notmatch '^https://') {
    throw "ApiBaseUrl must be an HTTPS URL."
}
if ($ApiBackupUrl -and $ApiBackupUrl -notmatch '^https://') {
    throw "ApiBackupUrl must be an HTTPS URL."
}
if ($ApiBackupUrl -and -not $ApiBaseUrl) {
    throw "ApiBackupUrl belongs to the deployment named by ApiBaseUrl; give both or neither."
}
$defines = @()
if ($ApiBaseUrl) {
    $defines += "--dart-define=API_BASE_URL=$ApiBaseUrl"
}
if ($ApiBackupUrl) {
    $defines += "--dart-define=API_BACKUP_URL=$ApiBackupUrl"
}
if ($DefinesFile) {
    $defines += "--dart-define-from-file=$((Resolve-Path -LiteralPath $DefinesFile).Path)"
}

$appRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$vendor = Join-Path $appRoot "third_party\flutter_v2ray_client"
if (-not (Test-Path -LiteralPath $vendor)) {
    throw "The patched flutter_v2ray_client is missing. Run third_party_src/vendor_plugin.py first."
}

Push-Location $appRoot
try {
    & (Join-Path $PSScriptRoot 'vendor_windows_runtime.ps1')
    if ($Offline) {
        flutter pub get --offline
    }
    else {
        flutter pub get
    }
    if ($LASTEXITCODE -ne 0) {
        throw "Flutter dependency resolution failed."
    }
    # A release build adds files to these and never removes any, so a
    # 72 MB kernel_blob.bin left by a debug run weeks earlier was shipped in
    # every portable zip. Start them empty.
    foreach ($stale in @("build\flutter_assets", "build\windows\x64\runner\Release")) {
        if (Test-Path -LiteralPath $stale) {
            Remove-Item -LiteralPath $stale -Recurse -Force
        }
    }
    flutter build windows --release --no-pub @defines
    if ($LASTEXITCODE -ne 0) {
        throw "Flutter failed to build the Windows release."
    }

    $bundle = Join-Path $appRoot "build\windows\x64\runner\Release"
    $sourceExecutable = Join-Path $bundle "nebula_mobile.exe"
    if (-not (Test-Path -LiteralPath $sourceExecutable)) {
        throw "Flutter did not produce its Windows executable at the expected x64 release path."
    }

    $destination = Join-Path $appRoot $OutputDirectory
    New-Item -ItemType Directory -Path $destination -Force | Out-Null
    $staging = Join-Path $destination "NebulaVPN-windows-x64-portable"
    if (Test-Path -LiteralPath $staging) {
        # This is a generated staging directory, not a user-selected input.
        # Recreate it so a previous executable cannot leave stale files in a
        # new portable release.
        Remove-Item -LiteralPath $staging -Recurse -Force
    }
    New-Item -ItemType Directory -Path $staging -Force | Out-Null
    Copy-Item -Path (Join-Path $bundle "*") -Destination $staging -Recurse -Force
    # Not Nebula.exe: Windows takes that name for a game's, Game Bar attaches
    # to it, and in Windows Sandbox the guest crashed seconds after it started.
    Rename-Item -LiteralPath (Join-Path $staging "nebula_mobile.exe") -NewName "NebulaVPN.exe"
    $archive = Join-Path $destination "NebulaVPN-windows-x64-portable.zip"
    if (Test-Path -LiteralPath $archive) {
        Remove-Item -LiteralPath $archive -Force
    }
    Compress-Archive -Path (Join-Path $staging "*") -DestinationPath $archive
    Write-Host "Portable bundle created: $archive"
}
finally {
    Pop-Location
}
