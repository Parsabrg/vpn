import 'dart:io';

/// The single elevated owner of any native Windows VPN tunnel (Xray or Hysteria)
/// and its temporary network routes and DNS policies.
///
/// What it writes goes to [windowsSessionOutputs], a folder only
/// administrators can change; it reads the app's stop request from the
/// session's own folder.
const String windowsVpnSupervisorScript = r'''
param(
  [string]$Engine,
  [string]$ArgumentsJson,
  [string]$State,
  [string]$UpstreamIp,
  [string]$DnsServersJson,
  [int]$OwnerPid,
  [string]$IsXray,
  [string]$KillSwitch = 'false',
  [string]$BlockedJson = '[]'
)
$ErrorActionPreference = 'Stop'
$stage = 'validating the VPN configuration'
$exitCode = 1
$child = $null
$adapter = $null
$ownedRoute = $null
$tunRoute0 = $null
$tunRoute128 = $null
$nrptName = $null
$dnsConfigured = $false
$ownerStart = $null
$ready = $false
$isXrayFlag = ($IsXray -eq 'true' -or $IsXray -eq '$true' -or $IsXray -eq '1')
$killSwitchFlag = ($KillSwitch -eq 'true')
$fwGroup = 'Nebula VPN kill switch'
$blocking = $false
$Out = $null

function Get-SelectedRoute([string]$Address) {
  return Find-NetRoute -RemoteIPAddress $Address -ErrorAction SilentlyContinue |
    Where-Object { $null -ne $_.DestinationPrefix } |
    Select-Object -First 1
}

function Test-OwnerAlive {
  $owner = Get-Process -Id $OwnerPid -ErrorAction SilentlyContinue
  return $null -ne $owner -and $owner.StartTime -eq $ownerStart
}

function Test-SessionAlive {
  if (Test-Path -LiteralPath (Join-Path $State 'stop')) { return $false }
  if (-not (Test-OwnerAlive)) { return $false }
  if ($null -eq $child) { return $false }
  $child.Refresh()
  return -not $child.HasExited
}

function Test-TunnelRoutes([string[]]$Addresses, [int]$InterfaceIndex) {
  foreach ($address in $Addresses) {
    try { $route = Get-SelectedRoute $address } catch { return $false }
    if ($null -eq $route -or $route.InterfaceIndex -ne $InterfaceIndex) {
      return $false
    }
  }
  return $true
}

try {
  # What runs as administrator writes only to a folder administrators own,
  # never the person's temp folder: there a link planted under a known name
  # would have the write land wherever it points. The app reads from here;
  # the one thing it writes, the stop request, is only checked for.
  $session = [IO.Path]::GetFileName($State)
  if ($session -notmatch '^[A-Za-z0-9._-]{1,80}$') { throw 'invalid state' }
  $base = Join-Path $env:ProgramData 'NebulaVPN'
  $runRoot = Join-Path $base 'run'
  foreach ($dir in @($base, $runRoot)) {
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
    if ((Get-Item -LiteralPath $dir -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'unsafe folder' }
    # Owned by Administrators, inherited by nothing else: SYSTEM and
    # Administrators change it, everyone else may only read.
    & icacls.exe $dir /setowner '*S-1-5-32-544' /Q | Out-Null
    & icacls.exe $dir /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'unsafe folder' }
  }
  Get-ChildItem -LiteralPath $runRoot -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-1) } |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
  $Out = Join-Path $runRoot $session
  if (Test-Path -LiteralPath $Out) { Remove-Item -LiteralPath $Out -Recurse -Force }
  New-Item -ItemType Directory -Path $Out | Out-Null

  $upstream = $null
  if (-not [System.Net.IPAddress]::TryParse($UpstreamIp, [ref]$upstream) -or
      $upstream.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
    throw 'invalid upstream'
  }
  # Assigned first, then wrapped: Windows PowerShell 5.1's ConvertFrom-Json
  # emits a JSON array as one object, so wrapping the call itself in @() is a
  # one-item list holding the whole array, every element check fails, and
  # every connect stopped at 'validating the VPN configuration'.
  $parsedResolvers = ConvertFrom-Json -InputObject $DnsServersJson
  $resolvers = @($parsedResolvers)
  if ($resolvers.Count -eq 0 -or $resolvers.Count -gt 8) { throw 'invalid DNS' }
  foreach ($resolver in $resolvers) {
    $parsed = $null
    if ($resolver -isnot [string] -or
        -not [System.Net.IPAddress]::TryParse($resolver, [ref]$parsed)) {
      throw 'invalid DNS'
    }
  }
  if (-not (Test-Path -LiteralPath $Engine -PathType Leaf) -or
      -not (Test-Path -LiteralPath $State -PathType Container)) {
    throw 'missing local file'
  }
  $ownerStart = (Get-Process -Id $OwnerPid).StartTime

  $stage = 'preserving the connection to the VPN server'
  $physicalRoute = Get-SelectedRoute $UpstreamIp
  if ($null -eq $physicalRoute -or $physicalRoute.InterfaceAlias -eq 'Nebula') {
    $physicalRoute = Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' -and $_.NextHop -ne '0.0.0.0' } | Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1
  }
  if ($null -eq $physicalRoute) { throw 'no physical gateway found' }

  $prefix = "$UpstreamIp/32"
  $existingRoute = Get-NetRoute -DestinationPrefix $prefix -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceIndex -eq $physicalRoute.InterfaceIndex } | Select-Object -First 1
  if ($null -eq $existingRoute) {
    $ownedRoute = New-NetRoute -DestinationPrefix $prefix -PolicyStore ActiveStore `
      -InterfaceIndex $physicalRoute.InterfaceIndex -NextHop $physicalRoute.NextHop -RouteMetric 1 -ErrorAction SilentlyContinue
  }

  $stage = 'starting the VPN process'
  $runtimeDir = Split-Path $Engine -Parent
  $parsedArgs = ConvertFrom-Json -InputObject $ArgumentsJson
  $argsList = @($parsedArgs)
  # The engine reads its config from the administrators' folder, copied
  # once, and one naming log files is refused: an engine running as
  # administrator would write them wherever they point.
  for ($i = 0; $i -lt $argsList.Count; $i++) {
    $arg = [string]$argsList[$i]
    if ($arg.StartsWith($State + '', [StringComparison]::OrdinalIgnoreCase)) {
      $item = Get-Item -LiteralPath $arg -Force
      if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'unsafe config' }
      $text = [IO.File]::ReadAllText($arg)
      if ($text -match '"(access|error)"\s*:\s*"(?!(none)?")[^"]*"') { throw 'unsafe config' }
      $copy = Join-Path $Out $item.Name
      [IO.File]::WriteAllText($copy, $text)
      $argsList[$i] = $copy
    }
  }
  $child = Start-Process -FilePath $Engine `
    -ArgumentList $argsList `
    -WorkingDirectory $runtimeDir `
    -WindowStyle Hidden -PassThru `
    -RedirectStandardError (Join-Path $Out 'engine.err') `
    -RedirectStandardOutput (Join-Path $Out 'engine.out')
  Set-Content -LiteralPath (Join-Path $Out 'xray.pid') -Value $child.Id -NoNewline

  $stage = 'creating the VPN adapter'
  for ($attempt = 0; $attempt -lt 80; $attempt++) {
    # An engine that cannot reach its server exits before it makes an
    # adapter (Hysteria2 to a blocked address does), which read as an
    # adapter fault.
    $child.Refresh()
    if ($child.HasExited) {
      $stage = 'connecting to the VPN server'
      throw 'engine exited'
    }
    if (-not (Test-SessionAlive)) { throw 'session stopped' }
    $adapter = Get-NetAdapter -IncludeHidden | Where-Object {
      $_.Name -eq 'Nebula' -and $_.Status -eq 'Up'
    } | Select-Object -First 1
    if ($null -ne $adapter) { break }
    Start-Sleep -Milliseconds 250
  }
  if ($null -eq $adapter) { throw 'adapter unavailable' }

  if ($isXrayFlag) {
    $stage = 'routing traffic through the VPN adapter'
    $tunRoute0 = New-NetRoute -DestinationPrefix '0.0.0.0/1' -InterfaceIndex $adapter.ifIndex -NextHop '0.0.0.0' -RouteMetric 5 -PolicyStore ActiveStore -ErrorAction SilentlyContinue
    $tunRoute128 = New-NetRoute -DestinationPrefix '128.0.0.0/1' -InterfaceIndex $adapter.ifIndex -NextHop '0.0.0.0' -RouteMetric 5 -PolicyStore ActiveStore -ErrorAction SilentlyContinue
  }

  $stage = 'configuring DNS through the VPN'
  Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $resolvers -ErrorAction SilentlyContinue
  $dnsConfigured = $true
  # One session runs at a time, so a rule of ours still here is a session
  # that ended without its cleanup (a crash, a power cut). Left, it kept
  # sending every lookup to the tunnel's resolver with the VPN off, and the
  # check below then added no rule of this session's own (seen 2026-10-17).
  Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
    Where-Object { $_.Comment -like 'Nebula VPN session *' } |
    ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force -ErrorAction SilentlyContinue }
  if (-not (Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object { @($_.Namespace) -contains '.' })) {
    $rule = Add-DnsClientNrptRule -Namespace '.' -NameServers $resolvers `
      -Comment ('Nebula VPN session ' + [IO.Path]::GetFileName($State)) -PassThru -ErrorAction SilentlyContinue
    if ($null -ne $rule) { $nrptName = $rule.Name }
    if ($null -ne $nrptName) {
      Set-Content -LiteralPath (Join-Path $Out 'nrpt-rule') -Value $nrptName -NoNewline
    }
  }
  Clear-DnsClientCache

  $stage = 'verifying full-device VPN routes'
  $routeChecks = @($resolvers) + @('1.1.1.1', '9.9.9.9')
  $routesReady = $false
  for ($attempt = 0; $attempt -lt 80; $attempt++) {
    if (-not (Test-SessionAlive)) { throw 'session stopped' }
    if (Test-TunnelRoutes $routeChecks $adapter.ifIndex) {
      $routesReady = $true
      break
    }
    Start-Sleep -Milliseconds 250
  }
  if (-not $routesReady) { throw 'incomplete routes' }

  # The kill switch: on the real adapters, nothing leaves but traffic to the
  # VPN server and the local network, and no DNS at all -- so a tunnel that
  # dies leaks nothing until it is back or the session is ended. Windows
  # Firewall rules, so it needs the firewall on; a profile with it off would
  # leave the rules inert while the app said protected.
  if ($killSwitchFlag) {
    $stage = 'turning on the kill switch (Windows Firewall must be on)'
    if (@(Get-NetFirewallProfile | Where-Object { -not $_.Enabled }).Count -gt 0) { throw 'firewall off' }
    $parsedBlocked = ConvertFrom-Json -InputObject $BlockedJson
    $blocked = @($parsedBlocked)
    if ($blocked.Count -eq 0) { throw 'invalid ranges' }
    foreach ($range in $blocked) {
      if ($range -isnot [string] -or $range -notmatch '^[0-9a-fA-F:.]+-[0-9a-fA-F:.]+$') { throw 'invalid ranges' }
    }
    $physical = @(Get-NetAdapter | Where-Object { $_.Name -ne 'Nebula' } | Select-Object -ExpandProperty Name)
    if ($physical.Count -eq 0) { throw 'no network adapter' }
    Get-NetFirewallRule -Group $fwGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    $blocking = $true
    New-NetFirewallRule -DisplayName $fwGroup -Group $fwGroup -Direction Outbound -Action Block `
      -InterfaceAlias $physical -RemoteAddress $blocked -Profile Any | Out-Null
    foreach ($protocol in @('UDP', 'TCP')) {
      New-NetFirewallRule -DisplayName "$fwGroup (DNS)" -Group $fwGroup -Direction Outbound -Action Block `
        -InterfaceAlias $physical -Protocol $protocol -RemotePort 53 -Profile Any | Out-Null
    }
  }

  New-Item -ItemType File -Path (Join-Path $Out 'routes-ready') -Force | Out-Null
  $ready = $true
  $exitCode = 0
  while (Test-SessionAlive) { Start-Sleep -Milliseconds 250 }
  $child.Refresh()
  if ($child.HasExited -and -not (Test-Path -LiteralPath (Join-Path $State 'stop')) -and (Test-OwnerAlive)) {
    Set-Content -LiteralPath (Join-Path $Out 'runtime.error') `
      -Value 'Windows VPN process stopped unexpectedly.' -NoNewline
    $exitCode = 1
    # With the kill switch the block outlives the tunnel: until the app
    # reconnects (stopping this session first) or disconnects, or is gone.
    if ($blocking) {
      while (-not (Test-Path -LiteralPath (Join-Path $State 'stop')) -and (Test-OwnerAlive)) {
        Start-Sleep -Milliseconds 250
      }
    }
  }
} catch {
  if (-not $ready -and $null -ne $Out) {
    Set-Content -LiteralPath (Join-Path $Out 'startup.error') `
      -Value ("Windows VPN failed while $stage.") -NoNewline -ErrorAction SilentlyContinue
  }
} finally {
  $cleanupFailed = $false
  if ($blocking) {
    try {
      Get-NetFirewallRule -Group $fwGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    } catch { $cleanupFailed = $true }
  }
  if ($null -ne $nrptName) {
    try { Remove-DnsClientNrptRule -Name $nrptName -Force } catch { $cleanupFailed = $true }
  }
  if ($isXrayFlag -and $null -ne $adapter) {
    try { Remove-NetRoute -DestinationPrefix '0.0.0.0/1' -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    try { Remove-NetRoute -DestinationPrefix '128.0.0.0/1' -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue } catch {}
  }
  if ($null -ne $child) {
    try {
      $child.Refresh()
      if (-not $child.HasExited) {
        Stop-Process -Id $child.Id -Force
        if (-not $child.WaitForExit(5000)) { $cleanupFailed = $true }
      }
    } catch { $cleanupFailed = $true }
  }
  if ($dnsConfigured -and $null -ne $adapter) {
    try {
      $remainingAdapter = Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceGuid -eq $adapter.InterfaceGuid } | Select-Object -First 1
      if ($null -ne $remainingAdapter) {
        Set-DnsClientServerAddress -InterfaceIndex $remainingAdapter.ifIndex -ResetServerAddresses -ErrorAction SilentlyContinue
      }
    } catch { $cleanupFailed = $true }
  }
  if ($null -ne $ownedRoute) {
    try { $ownedRoute | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue } catch { $cleanupFailed = $true }
  }
  try { Clear-DnsClientCache } catch { $cleanupFailed = $true }
  if ($cleanupFailed -and $null -ne $Out) {
    Set-Content -LiteralPath (Join-Path $Out 'cleanup.error') `
      -Value 'Windows could not fully restore the VPN network settings.' -NoNewline -ErrorAction SilentlyContinue
  }
  if ($null -ne $Out) {
    New-Item -ItemType File -Path (Join-Path $Out 'stopped') -Force -ErrorAction SilentlyContinue | Out-Null
  }
}
exit $exitCode
''';

/// Where the elevated supervisor leaves its files for the session in
/// [state]: a folder only administrators can change.
String windowsSessionOutputs(String state) =>
    '${Platform.environment['ProgramData'] ?? r'C:\ProgramData'}'
    r'\NebulaVPN\run\'
    '${state.split(r'\').last}';
