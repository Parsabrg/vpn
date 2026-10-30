<#!
.SYNOPSIS
Exercises the shipped Windows Hysteria2 + Xray TUN runtime against Nebula.

.DESCRIPTION
This is a manual release verification tool. It obtains a short-lived client
configuration from the API, starts Hysteria hidden, asks Windows for one UAC
approval to create the TUN adapter, and verifies broad routing, DNS, public
exit identity, and several unrelated HTTPS sites through that adapter.
No credentials, bearer tokens, or generated tunnel configuration are printed.
#>
[CmdletBinding()]
param(
  # The deployment's API, e.g. https://vpn.example.org (what the app pairs with).
  [Parameter(Mandatory)] [string] $ApiUrl,
  [Parameter(Mandatory)] [string] $Identifier,
  [Parameter(Mandatory)] [string] $Password,
  [string] $DeviceId = '',
  [string] $ServerCode = 'node-1',
  [string] $ProfileCode = 'hysteria2'
)

$ErrorActionPreference = 'Stop'
if ($ApiUrl -notmatch '^https://') { throw 'ApiUrl must be an https:// address.' }
$api = $ApiUrl.TrimEnd('/')
$runtime = Join-Path $PSScriptRoot '..\assets\windows_runtime'
$xray = Join-Path $runtime 'xray.exe'
$hysteria = Join-Path $runtime 'hysteria.exe'
if (-not (Test-Path -LiteralPath $xray) -or -not (Test-Path -LiteralPath $hysteria)) {
  throw 'The bundled Windows runtime is missing. Run tool\vendor_windows_runtime.ps1 first.'
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("nebula-live-test-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null
$hysteriaProcess = $null
$xraySupervisor = $null
try {
  $loginDeviceId = if ([string]::IsNullOrWhiteSpace($DeviceId)) { $null } else { $DeviceId }
  $loginBody = @{ identifier = $Identifier; password = $Password; device_id = $loginDeviceId; device_name = 'Nebula Windows live test'; platform = 'windows'; client_version = '1.0.0' } | ConvertTo-Json -Compress
  $login = Invoke-RestMethod -Method Post -Uri "$api/v1/auth/login" -ContentType 'application/json' -Body $loginBody
  $token = $login.access_token
  if ([string]::IsNullOrWhiteSpace($token)) { throw 'The API did not issue a session token.' }
  $headers = @{ Authorization = "Bearer $token" }
  if ([string]::IsNullOrWhiteSpace($DeviceId)) {
    $DeviceId = (Invoke-RestMethod -Method Get -Uri "$api/v1/auth/me" -Headers $headers).device_id
  }
  $clientBody = @{ server_code = $ServerCode; protocol_profile_code = $ProfileCode } | ConvertTo-Json -Compress
  $client = Invoke-RestMethod -Method Post -Uri "$api/v1/devices/$DeviceId/xray-client" -Headers $headers -ContentType 'application/json' -Body $clientBody
  if ($client.transport -ne 'hysteria') { throw 'The selected profile did not produce a Hysteria2 client.' }

  $proxyPort = Get-Random -Minimum 38000 -Maximum 45000
  $proxyUser = [guid]::NewGuid().ToString('N')
  $proxyPassword = [guid]::NewGuid().ToString('N')
  $yaml = @"
server: $($client.server_address):$($client.port)
auth: $($client.uuid):$($client.uuid)
tls:
  sni: $($client.sni)
  insecure: false
"@
  if ($null -ne $client.obfs_password -and $client.obfs_password.Length -gt 0) {
    $yaml += "`n" + @"
obfs:
  type: salamander
  salamander:
    password: $($client.obfs_password)
"@
  }
  $yaml += "`n" + @"
socks5:
  listen: 127.0.0.1:$proxyPort
  username: "$proxyUser"
  password: "$proxyPassword"
"@
  $yamlPath = Join-Path $work 'hysteria.yaml'
  Set-Content -LiteralPath $yamlPath -Value $yaml -NoNewline
  $hysteriaProcess = Start-Process -FilePath $hysteria -ArgumentList @('client', '-c', $yamlPath) -WindowStyle Hidden -PassThru -RedirectStandardError (Join-Path $work 'hysteria.err') -RedirectStandardOutput (Join-Path $work 'hysteria.out')
  Start-Sleep -Seconds 2
  if ($hysteriaProcess.HasExited) {
    $diagnostic = (Get-Content -LiteralPath (Join-Path $work 'hysteria.err') -Raw -ErrorAction SilentlyContinue)
    $diagnostic = $diagnostic.Replace($client.uuid, '[redacted]').Replace($proxyPassword, '[redacted]').Replace($proxyUser, '[redacted]')
    if ($null -ne $client.obfs_password) { $diagnostic = $diagnostic.Replace($client.obfs_password, '[redacted]') }
    throw "Hysteria2 exited before the tunnel could start: $diagnostic"
  }
  # The native TUN below is the actual product path.  It is tested directly
  # rather than through a separate SOCKS probe, which can hang during a
  # network transition on Windows.

  $xrayConfig = @{
    log = @{ loglevel = 'warning' }
    dns = @{ servers = @('tcp://94.140.14.140'); tag = 'nebula-dns' }
    inbounds = @(@{
      tag = 'tun-in'; protocol = 'tun'; settings = @{
        name = 'Nebula'; desc = 'Nebula VPN'; mtu = 1500
        gateway = @('172.19.0.1/30')
        dns = @('94.140.14.140')
        autoSystemRoutingTable = @('0.0.0.0/0')
        autoOutboundsInterface = 'auto'
      }
    })
    outbounds = @(@{
      tag = 'proxy'; protocol = 'socks'; settings = @{
        address = '127.0.0.1'; port = $proxyPort; user = $proxyUser; pass = $proxyPassword
      }
    }, @{
      tag = 'dns-out'; protocol = 'dns'
    })
    routing = @{ rules = @(
      @{ type = 'field'; inboundTag = @('tun-in'); port = '53'; outboundTag = 'dns-out' },
      @{ type = 'field'; inboundTag = @('nebula-dns'); outboundTag = 'proxy' }
    ) }
  } | ConvertTo-Json -Depth 12 -Compress
  $xrayPath = Join-Path $work 'xray.yaml'
  Set-Content -LiteralPath $xrayPath -Value $xrayConfig -NoNewline

  # Exercise Hysteria's official Windows TUN directly.  The SOCKS probe above
  # has already verified the authenticated profile; this avoids adding Xray as
  # a second forwarding hop.
  if ($null -ne $hysteriaProcess -and -not $hysteriaProcess.HasExited) {
    Stop-Process -Id $hysteriaProcess.Id -Force
    $hysteriaProcess.WaitForExit()
  }
  $serverIp = [System.Net.Dns]::GetHostAddresses($client.server_address) | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } | Select-Object -First 1 -ExpandProperty IPAddressToString
  if ([string]::IsNullOrWhiteSpace($serverIp)) { throw 'Could not resolve the Hysteria server for its tunnel exclusion route.' }
  $nativeTun = @"

tun:
  name: Nebula
  mtu: 1500
  address:
    ipv4: 100.100.100.101/30
    ipv6: 2001::ffff:ffff:ffff:fff1/126
  route:
    ipv4: [0.0.0.0/0]
    ipv6: ["2000::/3"]
    ipv4Exclude: [$serverIp/32]
"@
  $xray = $hysteria
  Set-Content -LiteralPath $xrayPath -Value ((Get-Content -LiteralPath $yamlPath -Raw) + $nativeTun) -NoNewline

  $runnerPath = Join-Path $work 'elevated-xray.ps1'
  @'
param([string]$Xray, [string]$Config, [string]$State, [string]$BypassAddress)
$physicalDefault = Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' -and $_.NextHop -ne '0.0.0.0' } | Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1
$process = Start-Process -FilePath $Xray -ArgumentList @('client', '-c', $Config) -WindowStyle Hidden -PassThru -RedirectStandardError (Join-Path $State 'xray.err') -RedirectStandardOutput (Join-Path $State 'xray.out')
Set-Content -LiteralPath (Join-Path $State 'xray.pid') -Value $process.Id -NoNewline
$adapter = $null
for ($attempt = 0; $attempt -lt 80; $attempt++) {
  $adapter = Get-NetAdapter -IncludeHidden | Where-Object { $_.Name -eq 'Nebula' -and $_.Status -eq 'Up' } | Select-Object -First 1
  if ($null -ne $adapter) { break }
  Start-Sleep -Milliseconds 250
}
if ($null -ne $adapter -and $null -ne $physicalDefault -and $BypassAddress -match '^\d{1,3}(\.\d{1,3}){3}$') {
  New-NetRoute -DestinationPrefix "$BypassAddress/32" -InterfaceIndex $physicalDefault.InterfaceIndex -NextHop $physicalDefault.NextHop -RouteMetric 1 -ErrorAction SilentlyContinue | Out-Null
}
while (-not (Test-Path -LiteralPath (Join-Path $State 'stop'))) {
  if ($process.HasExited) { exit $process.ExitCode }
  Start-Sleep -Milliseconds 250
}
if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force }
if ($null -ne $physicalDefault -and $BypassAddress -match '^\d{1,3}(\.\d{1,3}){3}$') { Remove-NetRoute -DestinationPrefix "$BypassAddress/32" -InterfaceIndex $physicalDefault.InterfaceIndex -Confirm:$false -ErrorAction SilentlyContinue }
'@ | Set-Content -LiteralPath $runnerPath -NoNewline
  $xraySupervisor = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $runnerPath, $xray, $xrayPath, $work, $serverIp) -Verb RunAs -WindowStyle Hidden -PassThru
  Write-Output 'Waiting for the Windows VPN adapter after one UAC approval...'
  $adapter = $null
  # The first Wintun installation can take noticeably longer than a normal
  # reconnect while Windows registers its network driver.
  for ($attempt = 0; $attempt -lt 160; $attempt++) {
    $adapter = Get-NetAdapter -IncludeHidden | Where-Object { $_.Name -eq 'Nebula' -and $_.Status -eq 'Up' } | Select-Object -First 1
    if ($null -ne $adapter) { break }
    Start-Sleep -Milliseconds 250
  }
  if ($null -eq $adapter) {
    $diagnostic = (Get-Content -LiteralPath (Join-Path $work 'xray.err') -Raw -ErrorAction SilentlyContinue)
    $diagnostic = $diagnostic.Replace($client.uuid, '[redacted]').Replace($proxyPassword, '[redacted]').Replace($proxyUser, '[redacted]')
    if ($null -ne $client.obfs_password) { $diagnostic = $diagnostic.Replace($client.obfs_password, '[redacted]') }
    throw "Windows did not create an active Nebula VPN adapter: $diagnostic"
  }
  $defaultRoute = $null
  for ($attempt = 0; $attempt -lt 20; $attempt++) {
    $defaultRoute = Get-NetRoute -AddressFamily IPv4 | Where-Object { ($_.DestinationPrefix -eq '0.0.0.0/0' -or $_.DestinationPrefix -eq '0.0.0.0/1') -and $_.InterfaceIndex -eq $adapter.ifIndex } | Select-Object -First 1
    if ($null -ne $defaultRoute) { break }
    Start-Sleep -Milliseconds 250
  }
  if ($null -eq $defaultRoute) { throw 'Hysteria did not install its VPN default route.' }
  & (Join-Path $PSScriptRoot 'verify_windows_tunnel.ps1') -ExpectedExitIp $serverIp
  if ($LASTEXITCODE -ne 0) {
    throw "Full-device verification did not pass (exit $LASTEXITCODE); see the checks above."
  }
}
finally {
  if (Test-Path -LiteralPath $work) { New-Item -ItemType File -Path (Join-Path $work 'stop') -Force | Out-Null }
  if ($null -ne $xraySupervisor) { $xraySupervisor.WaitForExit(5000) | Out-Null }
  if ($null -ne $hysteriaProcess -and -not $hysteriaProcess.HasExited) {
    Stop-Process -Id $hysteriaProcess.Id -Force
    $hysteriaProcess.WaitForExit()
  }
  if ((Test-Path -LiteralPath $work) -and $env:NEBULA_KEEP_TEST_LOGS -ne '1') { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
}
