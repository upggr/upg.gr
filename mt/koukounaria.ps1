# koukounaria.ps1
# Requires: Install-Module Posh-SSH -Scope CurrentUser -Force
Import-Module Posh-SSH -ErrorAction Stop

# -------- CONFIG --------
$BaseNet   = "192.168.208."
$StartIP   = 2              # set 101/101 to test one device first
$EndIP     = 253
$Username  = "admin"
$Password  = "is3rupgr.1821##"
$FetchUrl  = "https://upg.gr/mt/koukounaria.rsc"
$DstFile   = "koukounaria.rsc"
$SSID      = "Koukounaria Guest 9"
$DoUpdate  = $true          # set $false to skip RouterOS update
# ------------------------

# RouterOS command snippets
$CmdGetID      = ':put [/system identity get name]'
# Get first enabled ethernet MAC (no :break, safe on v6)
/* removed C-style comments */
$CmdGetMAC     = ':local e [/interface ethernet find where disabled=no]; :if ([:len $e]>0) do={:put ( [/interface ethernet get $e mac-address]->0 )} else={:put ""}'
$CmdGetVer     = ':put [/system resource get version]'
# Works even if wireless package is absent
$CmdHasWlan    = ':if ([:len [/interface find where type~"wlan"]]>0) do={:put WL} else={:put NOWL}'
$CmdChkSSID    = ":if ([:len [/interface wireless find where ssid=`"$SSID`"]] > 0) do={:put PRESENT} else={:put ABSENT}"
$CmdProvision  = @"
/tool fetch url=$FetchUrl dst=$DstFile check-certificate=no;
/import file-name=$DstFile;
"@
$CmdSetLT      = '/system package update set channel=long-term'
$CmdCheckUpd   = '/system package update check-for-updates'
$CmdGetInstVer = ':put [/system package update get installed-version]'
$CmdGetLatest  = ':put [/system package update get latest-version]'

function Ping-Fast($ip) { & ping.exe -n 1 -w 600 $ip 1>$null 2>$null; return ($LASTEXITCODE -eq 0) }
function Port22-Open($ip) { try { Test-NetConnection -ComputerName $ip -Port 22 -InformationLevel Quiet } catch { $false } }
function Try-SSH($ip, $user, $pass) {
  try {
    $credNone = New-Object PSCredential ($user,(ConvertTo-SecureString "" -AsPlainText -Force))
    $s = New-SSHSession -ComputerName $ip -Credential $credNone -AcceptKey -ErrorAction Stop
    return @{ Session=$s; Mode="nopass" }
  } catch {}
  try {
    $credPwd  = New-Object PSCredential ($user,(ConvertTo-SecureString $pass -AsPlainText -Force))
    $s = New-SSHSession -ComputerName $ip -Credential $credPwd -AcceptKey -ErrorAction Stop
    return @{ Session=$s; Mode="password" }
  } catch { return $null }
}

# Logs
$LogFile = ".\deploy-log.csv"
if (-not (Test-Path $LogFile)) {
  "IP,Identity,MAC,Version,Reachable,P22Open,AuthMode,SSIDAction,UpdateAction,Note" | Out-File -Encoding ascii $LogFile
}
$ts = Get-Date -Format "yyyyMMdd-HHmmss"
$SummaryFile = ".\deploy-summary-$ts.csv"
$Summary = New-Object System.Collections.Generic.List[object]

for ($i=$StartIP; $i -le $EndIP; $i++) {
  $ip = "$BaseNet$i"
  Write-Host "[$ip] Ping check..."
  if (-not (Ping-Fast $ip)) { "$ip,,,,'false','false',,,-,no ping" | Add-Content $LogFile; continue }

  # add summary row now; fill details if we can SSH
  $sumRow = [PSCustomObject]@{ IP=$ip; Identity=""; MAC=""; Version="" }

  $p22 = Port22-Open $ip
  if (-not $p22) {
    $Summary.Add($sumRow)
    "$ip,,,,'true','false',,,-,ssh closed" | Add-Content $LogFile
    continue
  }

  $conn = Try-SSH $ip $Username $Password
  if (-not $conn) {
    $Summary.Add($sumRow)
    "$ip,,,,'true','true',,,-,ssh auth failed" | Add-Content $LogFile
    continue
  }

  $session  = $conn.Session
  $identity=""; $mac=""; $ver=""; $ssidAction="n/a"; $updAction="n/a"
  try {
    $identity = ((Invoke-SSHCommand -SSHSession $session -Command $CmdGetID  -TimeOut 4000).Output -join "`n").Trim()
    $ver      = ((Invoke-SSHCommand -SSHSession $session -Command $CmdGetVer -TimeOut 4000).Output -join "`n").Trim()

    $macRaw   = (Invoke-SSHCommand -SSHSession $session -Command $CmdGetMAC -TimeOut 4000).Output -join "`n"
    $mac      = ([regex]::Match($macRaw,'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}')).Value

    $sumRow.Identity = $identity
    $sumRow.MAC      = $mac
    $sumRow.Version  = $ver
    $Summary.Add($sumRow)

    # skip provisioning on non-wireless boxes
    $wl = ((Invoke-SSHCommand -SSHSession $session -Command $CmdHasWlan -TimeOut 3000).Output -join "`n").Trim()
    if ($wl -eq 'NOWL') {
      $ssidAction = "no-wireless"
      "$ip,$identity,$mac,$ver,'true','true',$($conn.Mode),$ssidAction,$updAction," | Add-Content $LogFile
      continue
    }

    # SSID presence
    $chkOut = (Invoke-SSHCommand -SSHSession $session -Command $CmdChkSSID -TimeOut 4000).Output -join "`n"
    if ($chkOut -match 'PRESENT') {
      $ssidAction = "skipped"
    } else {
      $ssidAction = "provisioned"
      Invoke-SSHCommand -SSHSession $session -Command $CmdProvision | Out-Null
    }

    # Optional update
    if ($DoUpdate) {
      Invoke-SSHCommand -SSHSession $session -Command $CmdSetLT    | Out-Null
      Invoke-SSHCommand -SSHSession $session -Command $CmdCheckUpd | Out-Null
      $installed = ((Invoke-SSHCommand -SSHSession $session -Command $CmdGetInstVer -TimeOut 4000).Output -join "`n").Trim()
      $latest    = ((Invoke-SSHCommand -SSHSession $session -Command $CmdGetLatest  -TimeOut 4000).Output -join "`n").Trim()
      if ($latest -and $installed -and ($latest -ne $installed)) {
        try {
          Invoke-SSHCommand -SSHSession $session -Command '/system package update download-install' -TimeOut 120000 | Out-Null
          $updAction = "download-install to $latest"
        } catch {
          Invoke-SSHCommand -SSHSession $session -Command '/system package update download' -TimeOut 120000 | Out-Null
          Invoke-SSHCommand -SSHSession $session -Command '/system reboot without-prompt=yes' | Out-Null
          $updAction = "download+reboot to $latest"
        }
      } else {
        $updAction = "up-to-date ($installed)"
      }
    }

    "$ip,$identity,$mac,$ver,'true','true',$($conn.Mode),$ssidAction,$updAction," | Add-Content $LogFile
  } catch {
    "$ip,$identity,$mac,$ver,'true','true',$($conn.Mode),$ssidAction,$updAction,$($_.Exception.Message -replace ',',';')" | Add-Content $LogFile
  } finally {
    if ($session) { Remove-SSHSession -SSHSession $session | Out-Null }
  }
}

$Summary | Export-Csv -Path $SummaryFile -NoTypeInformation -Encoding UTF8
Write-Host "Summary: $SummaryFile"
Write-Host "Log:     $LogFile"