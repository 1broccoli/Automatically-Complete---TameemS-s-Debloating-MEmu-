# Requires: PowerShell 5+, Administrator
# Purpose: Debloat MEmu and set up LauncherHijack across all instances safely.

$ErrorActionPreference = 'Stop'

# Logging
try {
  $AutomationRoot = $PSScriptRoot
  $WorkspaceRoot = Split-Path -Parent $AutomationRoot
  $logDir = Join-Path $AutomationRoot 'logs'
  if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
  $log = Join-Path $logDir ("setup-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + ".log")
  Start-Transcript -Path $log -Force | Out-Null
} catch {}

# Ensure TLS 1.2 for GitHub API/Downloads on WinPS 5.1
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

# Resolve memuc.exe and common paths dynamically
function Get-MemucPath {
  $candidates = @(
    (Join-Path $WorkspaceRoot 'MEmu\memuc.exe'),
    (Join-Path $env:ProgramFiles 'Microvirt\MEmu\memuc.exe'),
    (Join-Path ${env:ProgramFiles(x86)} 'Microvirt\MEmu\memuc.exe')
  )
  foreach ($p in $candidates) { if ($p -and (Test-Path $p)) { return $p } }
  $cmd = (Get-Command memuc.exe -ErrorAction SilentlyContinue)
  if ($cmd) { return $cmd.Source }
  throw "memuc.exe not found. Install MEmu or adjust the script's paths."
}

$script:Memuc = Get-MemucPath
$script:DefaultDownloadDir = Join-Path ([Environment]::GetFolderPath('UserProfile')) 'Downloads\MEmu Download'
$script:SystemHosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'

function Get-MEmuIds {
  $list = & $script:Memuc listvms 2>$null
  if (-not $list) { return @() }
  return ($list -split "`n" | ForEach-Object { ($_ -split ',')[0] } | Where-Object { $_ -match '^\d+$' })
}

function Wait-Device($id, $timeoutSec=120) {
  $sw = [Diagnostics.Stopwatch]::StartNew()
  while ($sw.Elapsed.TotalSeconds -lt $timeoutSec) {
    try {
      $state = (& $script:Memuc adb -i $id get-state 2>$null)
    } catch { $state = $null }

    if ($state) {
      $s = $state.Trim()
      if ($s -eq 'device') { return $true }
      if ($s -eq 'offline' -or $s -eq 'unauthorized') {
        # Heal ADB
  & $script:Memuc adb kill-server 2>$null | Out-Null
        Start-Sleep -Seconds 1
  & $script:Memuc adb start-server 2>$null | Out-Null
      }
    }

  # Try explicit wait (ignore failures)
  try { & $script:Memuc adb -i $id wait-for-device 2>$null | Out-Null } catch {}
    Start-Sleep -Seconds 2
  }
  return $false
}

function Fetch-LauncherHijackApk($destDir) {
  try {
    if (-not (Test-Path $destDir)) { New-Item -Path $destDir -ItemType Directory -Force | Out-Null }
    $api = 'https://api.github.com/repos/BaronKiko/LauncherHijack/releases/latest'
    $resp = Invoke-RestMethod -Uri $api -Headers @{ 'User-Agent' = 'PowerShell' }
    $asset = $resp.assets | Where-Object { $_.name -match '\.apk$' } | Select-Object -First 1
    if ($asset -and $asset.browser_download_url) {
      $outFile = Join-Path $destDir ('LauncherHijack-' + $resp.tag_name + '.apk')
      Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $outFile -UseBasicParsing
      return $outFile
    }
  } catch { Write-Warning "Failed to auto-download LauncherHijack APK: $_" }
  return $null
}

function Get-LauncherHijackApk {
  $local = (Join-Path $WorkspaceRoot 'LauncherHijack-master\app\app-release.apk')
  if (Test-Path $local) { return $local }
  $dl = $script:DefaultDownloadDir
  if (Test-Path $dl) {
    $apk = Get-ChildItem -Path $dl -Filter '*.apk' -Recurse | Where-Object { $_.Name -match 'LauncherHijack|launcherhijack' } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($apk) { return $apk.FullName }
  }
  # Try to fetch if not found locally
  return (Fetch-LauncherHijackApk -destDir $dl)
}

function Install-ExtraApks($id) {
  $dl = $script:DefaultDownloadDir
  if (-not (Test-Path $dl)) { return }
  $apks = Get-ChildItem -Path $dl -Filter '*.apk' -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch 'LauncherHijack' }
  foreach ($apk in $apks) {
    try {
      Write-Host "[VM $id] Installing extra APK: $($apk.Name)" -ForegroundColor DarkCyan
      & $script:Memuc installapp -i $id "$($apk.FullName)" | Out-Null
    } catch { Write-Warning "[VM $id] Failed to install $($apk.Name): $_" }
  }
}

function Install-LauncherHijack($id, $apkPath) {
  Write-Host "[VM $id] Installing: $apkPath" -ForegroundColor Cyan
  & $script:Memuc installapp -i $id "$apkPath" | Out-Host
}

function Enable-LauncherHijack($id) {
  Write-Host "[VM $id] Enabling accessibility service" -ForegroundColor Cyan
  # Append to existing services to avoid clobbering
  $existing = (& $script:Memuc adb -i $id shell settings get secure enabled_accessibility_services 2>$null)
  $svc = 'com.baronkiko.launcherhijack/.AccServ'
  if (-not ($existing -and $existing.Trim() -match [regex]::Escape($svc))) {
    $newValue = if ($existing -and $existing.Trim() -ne 'null') { ($existing.Trim() + ':' + $svc) } else { $svc }
    & $script:Memuc adb -i $id shell settings put secure enabled_accessibility_services "$newValue" | Out-Null
  }
  & $script:Memuc adb -i $id shell settings put secure accessibility_enabled 1 | Out-Null
}

function Start-LHJ($id) {
  & $script:Memuc startapp -i $id com.baronkiko.launcherhijack/.MainActivity 2>$null | Out-Null
}

function Test-GuestRoot($id) {
  try {
    $out = (& $script:Memuc adb -i $id shell su -c id 2>$null)
    if ($out -and ($out -match 'uid=0')) { return $true }
  } catch {}
  try {
    $out2 = (& $script:Memuc adb -i $id shell id 2>$null)
    if ($out2 -and ($out2 -match 'uid=0')) { return $true }
  } catch {}
  return $false
}

function Enable-GuestRoot($id) {
  try {
    Write-Host "[VM $id] Enabling root in config (best-effort)" -ForegroundColor Yellow
    # Skip toggle if already rooted
    if (Test-GuestRoot -id $id) { Write-Host "[VM $id] Root already active; skipping toggle" -ForegroundColor DarkYellow; return }
    & $script:Memuc setconfigex -i $id root 1 2>$null | Out-Null
    & $script:Memuc reboot -i $id 2>$null | Out-Null
    if (-not (Wait-Device -id $id -timeoutSec 120)) { Write-Warning "[VM $id] Device not ready after root toggle" }
    # Try restarting adbd as root when available
    & $script:Memuc adb -i $id root 2>$null | Out-Null
  } catch { Write-Warning "[VM $id] Root toggle failed: $_" }
}

function Invoke-AdbShell($id, $cmd) {
  $ok = $false
  try {
    & $script:Memuc adb -i $id shell "$cmd" 2>&1 | Out-Null
    $ok = $true
  } catch {}
  if (-not $ok) {
    try {
      & $script:Memuc adb -i $id shell "su -c '$cmd'" 2>&1 | Out-Null
      $ok = $true
    } catch {}
  }
  return $ok
}

function Invoke-GuestDebloat($id) {
  Write-Host "[VM $id] Attempting guest debloat (requires root)" -ForegroundColor Yellow
  # Ensure adbd root if possible
  & $script:Memuc adb -i $id root 2>$null | Out-Null
  if (Test-GuestRoot -id $id) {
    $targets = @(
      '/system/priv-app/Guide',
      '/system/priv-app/MEmuGuide',
      '/system/priv-app/Launcher',
      '/system/priv-app/Launcher2',
      '/system/priv-app/Launcher3',
      '/system/priv-app/MEmuLauncher',
      '/system/priv-app/Installer',
      '/system/priv-app/MEmuInstaller',
      '/system/app/Guide',
      '/system/app/MEmuGuide',
      '/system/app/MEmuInstaller'
    )
    $rw = Invoke-AdbShell -id $id -cmd 'mount -o remount,rw /system'
    foreach ($p in $targets) { Invoke-AdbShell -id $id -cmd "rm -rf $p" | Out-Null }
    if ($rw) { Invoke-AdbShell -id $id -cmd 'mount -o remount,ro /system' | Out-Null }
  } else {
    Write-Host "[VM $id] Root not available; skipping file removals" -ForegroundColor DarkYellow
  }
  # Package-level fallback: disable Microvirt/MEmu packages only; do NOT disable user launchers
  $pkgs = (& $script:Memuc adb -i $id shell pm list packages 2>$null)
  $cands = @('com\.microvirt','com\.memu','microvirt','memu')
  $excludes = @('com\.baronkiko\.launcherhijack','com\.teslacoilsw\.launcher','com\.microsoft\.launcher')
  foreach ($line in $pkgs.Split("`n")) {
    $pkg = ($line -replace '^package:','').Trim()
    if (-not $pkg) { continue }
    $isCand = $false
    foreach ($c in $cands) { if ($pkg -match $c) { $isCand = $true; break } }
    if (-not $isCand) { continue }
    $isExcluded = $false
    foreach ($ex in $excludes) { if ($pkg -match $ex) { $isExcluded = $true; break } }
    if ($isExcluded) { continue }
  try { & $script:Memuc adb -i $id shell "pm disable-user --user 0 $pkg" 2>&1 | Out-Null } catch {}
  }
}

function Set-HostsBlock {
  $hosts = $script:SystemHosts
  $entries = @(
    '0.0.0.0 memuplay.com',
    '0.0.0.0 www.memuplay.com',
    '0.0.0.0 u888.v.baishan-cloud.net',
    '0.0.0.0 u999.v.bsclink.cn',
    '0.0.0.0 uz95.v.bsclink.cn',
    '0.0.0.0 ut89.v.bsclink.cn',
    '0.0.0.0 dl.memuplay.com',
    '0.0.0.0 www.microvirt.com',
    '0.0.0.0 microvirt.com',
    '0.0.0.0 hebei.22.121.in-addr.arpa',
    '0.0.0.0 d2bg5ibrp06389.cloudfront.net',
    '0.0.0.0 dl.memuplay.com.rgslb.net',
    '0.0.0.0 www.xyaz.cn.w.cdngslb.com',
    '0.0.0.0 d1ygnxto00lnhl.cloudfront.net',
    '0.0.0.0 d3p779s2xhx48e.cloudfront.net',
    '0.0.0.0 applovin.com',
    '0.0.0.0 rt.applovin.com',
    '0.0.0.0 ms.applovin.com',
    '0.0.0.0 d.applovin.com',
    '0.0.0.0 a.applovin.com',
    '0.0.0.0 prod-ms.applovin.com',
    '0.0.0.0 res1.applovin.com',
    '0.0.0.0 prod-a.applovin.com',
    '0.0.0.0 ms4.applovin.com',
    '0.0.0.0 assets.applovin.com',
    '0.0.0.0 prod-bid.applovin.com',
    '0.0.0.0 stage-ms.applovin.com',
    '0.0.0.0 img.applovin.com',
    '0.0.0.0 pdn.applovin.com',
    '0.0.0.0 prod-ms4.applovin.com',
    '0.0.0.0 stage-a.applovin.com',
    '0.0.0.0 gcp-prod-ms4.applovin.com',
    '0.0.0.0 info.applovin.com',
    '0.0.0.0 s.info.applovin.com',
    '0.0.0.0 rt-usa.applovin.com',
    '0.0.0.0 prod-a4.applovin.com',
    '0.0.0.0 stage-bid.applovin.com',
    '0.0.0.0 stage-ms4.applovin.com',
    '0.0.0.0 stage-assets.applovin.com',
    '0.0.0.0 gcp-stage-ms4.applovin.com',
    '0.0.0.0 gcp-ms4.applovin.com',
    '0.0.0.0 a-usa.applovin.com',
    '0.0.0.0 stage-img.applovin.com',
    '0.0.0.0 prod-mediate-events.applovin.com',
    '0.0.0.0 stage-pdn.applovin.com',
    '0.0.0.0 events.applovin.com',
    '0.0.0.0 dls-prod-mediate-cluster-al-p-ax-xxfz.events.applovin.com',
    '0.0.0.0 ewrprod-rtbwin.applovin.com',
    '0.0.0.0 gcp-ms.applovin.com',
    '0.0.0.0 nuqprod-rtbwin.applovin.com',
    '0.0.0.0 sfoprod-rtbwin.applovin.com',
    '0.0.0.0 prod-a-usa.applovin.com',
    '0.0.0.0 a4.applovin.com',
    '0.0.0.0 exp1-ms4.applovin.com',
    '0.0.0.0 gcp-a.applovin.com',
    '0.0.0.0 ewrstage-rtbwin.applovin.com',
    '0.0.0.0 stage-a4.applovin.com',
    '0.0.0.0 local-prod-bid.applovin.com',
    '0.0.0.0 gcp-img.applovin.com',
    '0.0.0.0 goog.applovin.com',
    '0.0.0.0 bid.applovin.com',
    '0.0.0.0 gcp-res1.applovin.com',
    '0.0.0.0 stage-mediate-events.applovin.com',
    '0.0.0.0 dash.applovin.com',
    '0.0.0.0 stage-a-usa.applovin.com',
    '0.0.0.0 sfostage-rtbwin.applovin.com',
    '0.0.0.0 ehd-stage-a.applovin.com',
    '0.0.0.0 hkg-prod-a.applovin.com',
    '0.0.0.0 ue.applovin.com',
    '0.0.0.0 vid.applovin.com',
    '0.0.0.0 ms-d.applovin.com',
    '0.0.0.0 www.applovin.com',
    '0.0.0.0 ehd-prod-bid.applovin.com',
    '0.0.0.0 stage-vid.applovin.com',
    '0.0.0.0 nyj-prod-a.applovin.com',
    '0.0.0.0 nrt-prod-a.applovin.com',
    '0.0.0.0 ams-prod-a.applovin.com',
    '0.0.0.0 safedk.applovin.com',
    '0.0.0.0 r.applovin.com',
    '0.0.0.0 img2.applovin.com',
    '0.0.0.0 assets2.applovin.com',
    '0.0.0.0 dls-stage-bid.applovin.com',
    '0.0.0.0 amsstage-rtbwin.applovin.com',
    '0.0.0.0 amsprod-rtbwin.applovin.com',
    '0.0.0.0 sfo-prod-a.applovin.com'
  )
  $marker = '# Added by setup-memu.ps1'
  try {
    $content = Get-Content -Path $hosts -ErrorAction Stop
    if ($content -notcontains $marker) {
      Add-Content -Path $hosts -Value $marker -Encoding ASCII
      foreach ($e in $entries) { Add-Content -Path $hosts -Value $e -Encoding ASCII }
    }
  } catch {
    Write-Warning "Hosts file is locked; deferring changes to startup and rebooting."
    # Write a small startup script to apply hosts changes
  $apply = (Join-Path $AutomationRoot 'apply-hosts.ps1')
    $entriesLiteral = ($entries | ForEach-Object { "'$_'" }) -join ",\n    "
    $script = @"
param()
$hosts = 'C:\\Windows\\System32\\drivers\\etc\\hosts'
$marker = '# Added by setup-memu.ps1'
$entries = @(
    $entriesLiteral
)
try {
  $content = Get-Content -Path $hosts -ErrorAction SilentlyContinue
  if (-not $content) { $content = @() }
  if ($content -notcontains $marker) {
    Add-Content -Path $hosts -Value $marker -Encoding ASCII
    foreach ($e in $entries) { Add-Content -Path $hosts -Value $e -Encoding ASCII }
  }
} catch {}
try { Unregister-ScheduledTask -TaskName 'MEmu-ApplyHosts' -Confirm:$false -ErrorAction SilentlyContinue } catch {}
try { Remove-Item -Path $MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue } catch {}
"@
    Set-Content -Path $apply -Value $script -Encoding ASCII -Force
    try {
      $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-ExecutionPolicy Bypass -NoProfile -File `"$apply`""
      $trigger = New-ScheduledTaskTrigger -AtStartup
      Register-ScheduledTask -TaskName 'MEmu-ApplyHosts' -Action $action -Trigger $trigger -RunLevel Highest -Force | Out-Null
    } catch { Write-Warning "Failed to register startup task for hosts changes: $_" }
    # Reboot to release file lock and apply hosts
    try { Start-Process -FilePath shutdown.exe -ArgumentList '/r','/t','10','/c','"Completing MEmu hosts configuration"' -WindowStyle Hidden } catch {}
  }
}

function Set-FirewallBlock {
  $candidates = @(
    (Join-Path $WorkspaceRoot 'memu_block.txt'),
    (Join-Path $AutomationRoot 'memu_block.txt')
  )
  $blockFile = $null
  foreach ($c in $candidates) { if (Test-Path $c) { $blockFile = $c; break } }
  if (-not $blockFile) {
    Write-Warning "Blocklist memu_block.txt not found in workspace or automation folder; skipping firewall rules."
    return
  }
  Write-Host "Applying Windows Firewall IP rules from memu_block.txt" -ForegroundColor Yellow
  try {
    $raw = Get-Content -Path $blockFile -Raw
    $ips = $raw -split '[,\s]+' | Where-Object { $_ -and $_.Trim().Length -gt 0 } | ForEach-Object { $_.Trim() } | Select-Object -Unique
    if (-not $ips -or $ips.Count -eq 0) { Write-Warning 'No IPs found in memu_block.txt'; return }
    # Remove existing rule if present
    & netsh advfirewall firewall delete rule name="memu_ip_to_fw_rule" | Out-Null
    # Chunk IPs to avoid command length limits
    $chunkSize = 50
    for ($i=0; $i -lt $ips.Count; $i += $chunkSize) {
      $chunk = ($ips[$i..([Math]::Min($i+$chunkSize-1,$ips.Count-1))] -join ',')
      & netsh advfirewall firewall add rule name="memu_ip_to_fw_rule" protocol=any dir=in action=block remoteip=$chunk | Out-Null
      & netsh advfirewall firewall add rule name="memu_ip_to_fw_rule" protocol=any dir=out action=block remoteip=$chunk | Out-Null
    }
  } catch { Write-Warning "Failed to apply firewall rules: $_" }
}

# Main
$ids = Get-MEmuIds
if (-not $ids) { Write-Error 'No MEmu instances found.'; exit 1 }
Write-Host "Found MEmu instances: $($ids -join ', ')" -ForegroundColor Green

$apk = Get-LauncherHijackApk
if (-not $apk) {
  Write-Warning ("LauncherHijack APK not found. Place it in '{0}' and re-run." -f $script:DefaultDownloadDir)
} else {
  foreach ($id in $ids) {
    & $script:Memuc start -i $id | Out-Null
    if (-not (Wait-Device -id $id -timeoutSec 180)) { Write-Warning "[VM $id] ADB not ready"; continue }
  Enable-GuestRoot -id $id
    Install-LauncherHijack -id $id -apkPath $apk
  Install-ExtraApks -id $id
    Enable-LauncherHijack -id $id
    Start-LHJ -id $id
  Invoke-GuestDebloat -id $id
  }
}

Set-HostsBlock
Set-FirewallBlock

Write-Host 'All done. Reboot VMs and set your preferred launcher in LauncherHijack if prompted.' -ForegroundColor Green

try { Stop-Transcript | Out-Null } catch {}
