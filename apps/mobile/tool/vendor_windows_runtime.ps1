[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$destination = Join-Path $root 'assets\windows_runtime'
$xrayVersion = 'v26.9.30'
$xrayHash = 'B17A619343C11B89D8FAF36278298856749B15C52277D875D32051B33DCDA617'
$hysteriaHash = '807AE5332A8FEFEEFF804923E057B6942ACCEAA11706AC7FA3DB42F192C2FDE1'

New-Item -ItemType Directory -Path $destination -Force | Out-Null

function Get-VerifiedAsset([string]$Url, [string]$Destination, [string]$ExpectedHash) {
    Invoke-WebRequest -Uri $Url -OutFile $Destination
    $actual = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash
    if ($actual -ne $ExpectedHash) {
        throw "SHA-256 mismatch for $(Split-Path $Destination -Leaf): expected $ExpectedHash, got $actual"
    }
}

$temporary = Join-Path $env:TEMP 'nebula-xray-windows.zip'
try {
    Get-VerifiedAsset "https://github.com/XTLS/Xray-core/releases/download/$xrayVersion/Xray-windows-64.zip" $temporary $xrayHash
    Expand-Archive -LiteralPath $temporary -DestinationPath $destination -Force
    if (-not (Test-Path -LiteralPath (Join-Path $destination 'wintun.dll'))) {
        throw 'The official Xray Windows archive did not contain wintun.dll.'
    }
    Get-VerifiedAsset 'https://github.com/HyNetworks/hysteria/releases/download/app/v2.12.2/hysteria-windows-amd64.exe' (Join-Path $destination 'hysteria.exe') $hysteriaHash
}
finally {
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
}
