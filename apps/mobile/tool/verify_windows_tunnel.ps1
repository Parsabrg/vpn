<#
.SYNOPSIS
Read-only verification of an already connected Nebula Windows VPN.

.DESCRIPTION
Does not sign in, request elevation, read private tunnel configuration, or
change networking. Uses normal system DNS and HTTPS requests without a proxy
override or pinned destination addresses. Verifies broad routes, effective DNS
routes, source addresses, and the public exit address.

Exit 0: IPv4 and IPv6 checks passed.
Exit 1: A connectivity, routing, DNS, or exit-address check failed.
Exit 2: IPv4 passed, but IPv6 is unavailable or could not be fully verified.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)] [System.Net.IPAddress] $ExpectedExitIp,
  [System.Net.IPAddress] $ExpectedIPv6ExitIp,
  [string] $AdapterName = 'Nebula',
  [ValidateRange(5, 60)] [int] $TimeoutSeconds = 20,
  [string[]] $TestUrls = @(
    'https://www.youtube.com/generate_204',
    'https://www.wikipedia.org/',
    'https://www.microsoft.com/'
  )
)

$ErrorActionPreference = 'Stop'
$script:failures = 0
$script:ipv6Unverified = $false

function Write-Failure([string] $Message) {
  $script:failures++
  Write-Output "FAIL: $Message"
}

function Get-EffectiveRoute([string] $Address) {
  # Find-NetRoute uses Windows' route selection, including interface metrics.
  # It returns both an IP address and a route; keep only the route object.
  @(Find-NetRoute -RemoteIPAddress $Address -ErrorAction SilentlyContinue |
    Where-Object { $null -ne $_.DestinationPrefix }) | Select-Object -First 1
}

function Test-TunnelRoute([string] $Address, [string] $Purpose) {
  $route = Get-EffectiveRoute $Address
  if ($null -eq $route) {
    Write-Failure "$Purpose has no usable route ($Address)."
    return $false
  }
  if ($route.InterfaceIndex -ne $script:tunnelIndex) {
    Write-Failure "$Purpose bypasses the VPN via $($route.InterfaceAlias) ($Address)."
    return $false
  }
  return $true
}

function Invoke-HttpsProbe([string] $Url, [string] $Family, [switch] $ReadBody) {
  $uri = [uri] $Url
  if ($uri.Scheme -ne 'https' -or -not [string]::IsNullOrEmpty($uri.UserInfo)) {
    throw 'Verification URLs must be HTTPS URLs without credentials.'
  }
  $curlArgs = @('--silent', '--show-error', '--noproxy', '*',
    '--connect-timeout', '10', '--max-time', "$TimeoutSeconds", '--proto', '=https',
    '--write-out', "`nNEBULA_META %{http_code} %{local_ip} %{remote_ip}")
  $curlArgs += if ($Family -eq 'IPv6') { '--ipv6' } else { '--ipv4' }
  if (-not $ReadBody) { $curlArgs += @('--output', 'NUL') }
  $curlArgs += $uri.AbsoluteUri
  try {
    $raw = @(& $script:curlPath @curlArgs 2>&1)
    $exitCode = $LASTEXITCODE
  }
  catch {
    Write-Failure "$Family HTTPS request to $($uri.Host) failed: $($_.Exception.Message)"
    return
  }
  $meta = [regex]::Match(($raw -join "`n"), '(?m)^NEBULA_META (\d{3}) (\S+) (\S+)\s*$')
  if ($exitCode -ne 0 -or -not $meta.Success) {
    Write-Failure "$Family HTTPS request to $($uri.Host) failed (curl exit $exitCode)."
    return
  }
  $status = [int] $meta.Groups[1].Value
  $localIp = $meta.Groups[2].Value
  $remoteIp = $meta.Groups[3].Value
  if ($status -lt 200 -or $status -ge 400) {
    Write-Failure "$Family HTTPS request to $($uri.Host) returned HTTP $status."
    return
  }
  $sourceAddress = [System.Net.IPAddress]::Parse($localIp)
  if (-not ($script:tunnelAddresses | Where-Object { ([System.Net.IPAddress]::Parse($_)).Equals($sourceAddress) })) {
    Write-Failure "$Family HTTPS request to $($uri.Host) used source $localIp outside the VPN adapter."
    return
  }
  # Suppress the boolean helper result; its FAIL messages are still visible.
  $routeResult = @(Test-TunnelRoute $remoteIp "HTTPS destination $($uri.Host)")
  $routeResult | Where-Object { $_ -is [string] } | Write-Output
  if ($routeResult[-1] -ne $true) { return }
  Write-Output "PASS: $Family $($uri.Host) HTTP $status; source $localIp on $AdapterName."
  if ($ReadBody) {
    $body = (($raw -join "`n") -replace '(?m)^NEBULA_META .*$', '').Trim()
    return [pscustomobject] @{ Body = $body }
  }
}

try {
  if ($ExpectedExitIp.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
    throw 'ExpectedExitIp must be the VPN server public IPv4 exit address.'
  }
  if ($null -ne $ExpectedIPv6ExitIp -and $ExpectedIPv6ExitIp.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
    throw 'ExpectedIPv6ExitIp must be an IPv6 address.'
  }
  if ($TestUrls.Count -lt 3 -or @($TestUrls | ForEach-Object { ([uri] $_).Host } | Select-Object -Unique).Count -lt 3) {
    throw 'Provide at least three HTTPS URLs on distinct hosts.'
  }
  $script:curlPath = (Get-Command curl.exe -CommandType Application -ErrorAction Stop).Source
  $adapter = @(Get-NetAdapter -IncludeHidden | Where-Object { $_.Name -eq $AdapterName -and $_.Status -eq 'Up' })
  if ($adapter.Count -ne 1) { throw "Exactly one active $AdapterName adapter is required. Connect Nebula first." }
  $script:tunnelIndex = $adapter[0].ifIndex
  $script:tunnelAddresses = @(Get-NetIPAddress -InterfaceIndex $script:tunnelIndex |
    Where-Object { $_.AddressState -eq 'Preferred' } | Select-Object -ExpandProperty IPAddress)
  Write-Output "Checking the connected $AdapterName adapter without changing system networking."

  $v4Prefixes = @(Get-NetRoute -AddressFamily IPv4 -InterfaceIndex $script:tunnelIndex | Select-Object -ExpandProperty DestinationPrefix)
  if ($v4Prefixes -notcontains '0.0.0.0/0' -and
      -not ($v4Prefixes -contains '0.0.0.0/1' -and $v4Prefixes -contains '128.0.0.0/1')) {
    Write-Failure 'The VPN does not install routes covering all IPv4 internet destinations.'
  }
  else { Write-Output 'PASS: VPN routes cover the whole IPv4 address space.' }
  # Route selection only: these checks do not send packets to these addresses.
  foreach ($address in @('1.1.1.1', '8.8.8.8', '208.67.222.222')) {
    $result = @(Test-TunnelRoute $address 'IPv4 internet traffic')
    $result | Where-Object { $_ -is [string] } | Write-Output
  }

  $connectedIndices = @(Get-NetIPInterface | Where-Object { $_.ConnectionState -eq 'Connected' } | Select-Object -ExpandProperty InterfaceIndex -Unique)
  $nrpt = @(Get-DnsClientNrptPolicy -Effective)
  $rootNrpt = @($nrpt | Where-Object { $_.Namespace -contains '.' -and @($_.NameServers).Count -gt 0 })
  $dnsCandidates = @()
  if ($rootNrpt.Count -gt 0) {
    # A root NRPT policy selects the resolver for names without a more-specific
    # policy. Underlying WiFi/Ethernet DNS is retained for disconnect, but is not
    # selected while that root rule is effective.
    Write-Output 'INFO: effective root NRPT policy selects VPN DNS; underlying interface resolver settings are not selected.'
  }
  else {
    $dnsCandidates += @(Get-DnsClientServerAddress | Where-Object { $connectedIndices -contains $_.InterfaceIndex } |
      ForEach-Object { $_.ServerAddresses })
  }
  # More-specific policies override the root rule, so include their resolvers
  # even when the root rule protects ordinary lookups.
  $dnsCandidates += @($nrpt | ForEach-Object { $_.NameServers })
  $dns = @($dnsCandidates | ForEach-Object { ([string] $_) -split '[,;\s]+' } |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
  if ($dns.Count -eq 0) { Write-Failure 'No DNS server is configured on a connected interface.' }
  $reachableDns = 0
  foreach ($server in $dns) {
    $dnsRoute = Get-EffectiveRoute $server
    if ($null -eq $dnsRoute) {
      Write-Output "INFO: DNS resolver $server has no active route."
    }
    elseif ($dnsRoute.InterfaceIndex -ne $script:tunnelIndex) {
      $reachableDns++
      Write-Failure "DNS resolver $server is reachable outside the VPN via $($dnsRoute.InterfaceAlias); Windows DNS may leak."
    }
    else {
      $reachableDns++
      Write-Output "PASS: DNS resolver $server routes through $AdapterName."
    }
  }
  if ($dns.Count -gt 0 -and $reachableDns -eq 0) { Write-Failure 'No selected DNS resolver has a usable route.' }

  foreach ($url in $TestUrls) { Invoke-HttpsProbe $url 'IPv4' }
  $exitProbe = @(Invoke-HttpsProbe 'https://api.ipify.org/' 'IPv4' -ReadBody)
  $exitProbe | Where-Object { $_ -is [string] } | Write-Output
  $exitBody = $exitProbe | Where-Object { $null -ne $_.Body } | Select-Object -Last 1
  if ($null -ne $exitBody) {
    $observedExit = $null
    if (-not [System.Net.IPAddress]::TryParse($exitBody.Body, [ref] $observedExit) -or -not $ExpectedExitIp.Equals($observedExit)) {
      Write-Failure "Public IPv4 exit does not match the expected VPN exit $ExpectedExitIp."
    }
    else { Write-Output "PASS: public IPv4 exit matches the VPN server ($ExpectedExitIp)." }
  }

  $v6Route = Get-EffectiveRoute '2606:4700:4700::1111'
  if ($null -eq $v6Route) {
    Write-Output 'UNVERIFIED: no usable IPv6 internet route; IPv6 connectivity cannot be tested on this connection.'
    $script:ipv6Unverified = $true
  }
  elseif ($v6Route.InterfaceIndex -ne $script:tunnelIndex) {
    Write-Failure "IPv6 internet traffic bypasses the VPN via $($v6Route.InterfaceAlias)."
  }
  else {
    $v6Prefixes = @(Get-NetRoute -AddressFamily IPv6 -InterfaceIndex $script:tunnelIndex | Select-Object -ExpandProperty DestinationPrefix)
    if ($v6Prefixes -notcontains '::/0' -and $v6Prefixes -notcontains '2000::/3' -and
        -not ($v6Prefixes -contains '::/1' -and $v6Prefixes -contains '8000::/1')) {
      Write-Failure 'The VPN does not cover the global IPv6 internet address space.'
    }
    else { Write-Output 'PASS: VPN routes cover the global IPv6 internet address space.' }
    foreach ($url in $TestUrls) { Invoke-HttpsProbe $url 'IPv6' }
    $exitProbe6 = @(Invoke-HttpsProbe 'https://api64.ipify.org/' 'IPv6' -ReadBody)
    $exitProbe6 | Where-Object { $_ -is [string] } | Write-Output
    $exitBody6 = $exitProbe6 | Where-Object { $null -ne $_.Body } | Select-Object -Last 1
    if ($null -eq $ExpectedIPv6ExitIp) {
      Write-Output 'UNVERIFIED: supply ExpectedIPv6ExitIp to verify the public IPv6 exit identity.'
      $script:ipv6Unverified = $true
    }
    elseif ($null -ne $exitBody6) {
      $observedExit6 = $null
      if (-not [System.Net.IPAddress]::TryParse($exitBody6.Body, [ref] $observedExit6) -or -not $ExpectedIPv6ExitIp.Equals($observedExit6)) {
        Write-Failure "Public IPv6 exit does not match the expected VPN exit $ExpectedIPv6ExitIp."
      }
      else { Write-Output "PASS: public IPv6 exit matches the VPN server ($ExpectedIPv6ExitIp)." }
    }
  }
}
catch {
  Write-Failure $_.Exception.Message
}

if ($script:failures -gt 0) {
  Write-Output "RESULT: FAILED ($script:failures checks); full-device VPN protection was not verified."
  exit 1
}
if ($script:ipv6Unverified) {
  Write-Output 'RESULT: IPv4 checks passed; IPv6 remains unverified. This is not a full dual-stack pass.'
  exit 2
}
Write-Output 'RESULT: PASS. Broad routing, DNS paths, unrelated HTTPS sites, and IPv4/IPv6 exits were verified.'
exit 0
