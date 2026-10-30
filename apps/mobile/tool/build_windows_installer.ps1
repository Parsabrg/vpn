param(
    # Passed through to build_windows_portable.ps1: the same build makes both.
    [string]$ApiBaseUrl,
    [string]$ApiBackupUrl,
    [string]$DefinesFile,
    [string]$OutputDirectory = "dist",
    [switch]$Offline
)

# Builds the portable zip and, from the same Flutter build, the install wizard
# (NebulaVPN-windows-x64-setup.exe) with Inno Setup 6.
$ErrorActionPreference = "Stop"

$iscc = @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $iscc) {
    throw "Inno Setup 6 is not installed (winget install JRSoftware.InnoSetup)."
}

$portable = @{ OutputDirectory = $OutputDirectory; Offline = $Offline }
if ($ApiBaseUrl) { $portable.ApiBaseUrl = $ApiBaseUrl }
if ($ApiBackupUrl) { $portable.ApiBackupUrl = $ApiBackupUrl }
if ($DefinesFile) { $portable.DefinesFile = $DefinesFile }
& (Join-Path $PSScriptRoot "build_windows_portable.ps1") @portable

$appRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$destination = Join-Path $appRoot $OutputDirectory
& $iscc "/O$destination" (Join-Path $appRoot "windows\installer\nebula.iss")
if ($LASTEXITCODE -ne 0) {
    throw "Inno Setup failed to build the installer."
}
Write-Host "Installer created: $(Join-Path $destination 'NebulaVPN-windows-x64-setup.exe')"
