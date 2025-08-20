Import-Module Posh-SSH -ErrorAction Stop

# -------- CONFIG --------
$BaseNet   = "192.168.208."
$StartIP   = 2
$EndIP     = 253
$Username  = "admin"
$Password  = "is3rupgr.1821##"
$FetchUrl  = "https://upg.gr/mt/koukounaria.rsc"
$DstFile   = "koukounaria.rsc"
$SSID      = "Koukounaria Guest 9"
$DoUpdate  = $true     # set $false to disable RouterOS updates
# ------------------------

# RouterOS one-liners (safe on v6)
$CmdGetID       = ':put [/system identity get name]'
$CmdGetVer      = ':put [/system resource get version]'
# ether1 MAC if exists, else first enabled ethernet MAC
$CmdGetMacE1    = ':local i [/interface ethernet find where name="ether1"]; :if ([:len $i]>0) do={:put [/interface ethernet get $i mac-address]} else={:local e [/interface ethernet find where disabled=no]; :if ([:len $e]>0) do={:put ( [/interface ethernet get $e mac-address]->0 )} else={:put ""}}'
# SSIDs per radio (blank if radio missing)
$CmdGetSSID1    = ':if ([:len [/interface wireless find where name="wlan1"]]>0) do={:put [/interface wireless get wlan1 ssid]} else={:put ""}'
$CmdGetSSID2    = ':if ([:len [/interface wireless find where name="wlan2"]]>0) do={:put [/interface wireless get wlan2 ssid]} else={:put ""}'
# presence of any wireless interface
$CmdHasWlan     = ':if ([:len [/interface find where type~"wlan"]]>0) do={:put WL} else={:put NOWL}'
# SSID presence check for idempotency
$CmdChkSSID     = ":if ([:len [/interface wireless find where ssid=`"$SSID`"]] > 0) do={:put PRESENT} else={:put ABSENT}"
# provisioning via remote RSC
$CmdProvision   = @"
/tool fetch url=$FetchUrl dst=$DstFile check-certificate=no;
/import file-name=$DstFile;
"@
# update helpers
$CmdSetLT       = '/system package update set channel=long-term'
$CmdCheckUpd    = '/system package update check-for-updates'
$CmdGetInstVer  = ':put [/system package update get installed-version]'
$CmdGetLatest   = ':put [/system package update get latest-version]'

function Ping-Fast($ip) { & ping.exe -n 1 -w 600 $ip 1>$null 2>$null; return ($LASTEXITCODE -eq 0) }
function Port22-Open($ip) { try { Test-NetConnection -ComputerName $ip -Port 22 -InformationLevel Quiet } catch { $false } }
function Try-SSH($ip, $user, $pass) {
  try { $c1 = New-Object PSCredential ($user,(ConvertTo-SecureString "" -AsPlainText -Force))
        $s1 = New-SSHSession -ComputerName $ip -Credential $c1 -AcceptKey -ErrorAction Stop
        return @{ Session=$s1; Mode="nopass" } } catch {}
  try { $c2 = New-Object PSCredential ($user,(ConvertTo-SecureString $pass -AsPlainText -Force))
        $s2 = New-SSHSession -ComputerName $ip -Credential $c2 -AcceptKey -ErrorAction Stop
        return @{ Session=$s2; Mode="password" } } catch { return $null }
}

# Logs
$LogFile = ".\deploy-log.csv"
if (-not (Test-Path $LogFile)) {
  "IP,Identity,MAC,Version,SSID_wlan1,SSID_wlan2,Reachable,P22Open,AuthMode,SSIDAction,UpdateAction,Note" | Out-File -Encoding ascii $LogFile
}
$ts = Get-Date -Format "yyyyMMdd-HHmmss"
$SummaryFile = ".\deploy-summary-$ts.csv"
$Summary = New-Object System.Collections.Generic.List[object]

for ($i=$StartIP; $i -le $EndIP; $i++) {
  $ip = "$BaseNet$i"
  Write-Host "[$ip] Ping check..."
  if (-not (Ping-Fast $ip)) { "$ip,,,,,`'false`',`'false`',,,-,no ping" | Add-Content $LogFile; continue }

  # Detected host → prepare a summary row (fill details on SSH success)
  $sumRow = [PSCustomObject]@{ IP=$ip; Identity=""; MAC=""; Version=""; SSID_wlan1=""; SSID_wlan2="" }

  if (-not (Port22-Open $ip)) {
    $Summary.Add($sumRow)
    "$ip,,,,,`'true`',`'false`',,,-,ssh closed" | Add-Content $LogFile
    continue
  }

  $conn = Try-SSH $ip $Username $Password
  if (-not $conn) {
    $Summary.Add($sumRow)
    "$ip,,,,,`'true`',`'true`',,,-,ssh auth failed" | Add-Content $LogFile
    continue
  }

  $session = $conn.Session
  $identity=""; $mac=""; $ver=""; $ssid1=""; $ssid2=""; $ssidAction="n/a"; $updAction="n/a"

  try {
    # If we logged in with NO password, set one now
    if ($conn.Mode -eq "nopass") {
      $CmdSetPwd = "/user set [find name=$Username] password=`"$Password`""
      Invoke-SSHCommand -SSHSession $session -Command $CmdSetPwd | Out-Null
      Write-Host "[$ip] Password set for user '$Username'." -ForegroundColor Magenta
    }

    # Gather details
    $identity = ((Invoke-SSHCommand -SSHSession $session -Command $CmdGetID  -TimeOut 4000).Output -join "`n").Trim()
    $ver      = ((Invoke-SSHCommand -SSHSession $session -Command $CmdGetVer -TimeOut 4000).Output -join "`n").Trim()
    $macRaw   =  (Invoke-SSHCommand -SSHSession $session -Command $CmdGetMacE1 -TimeOut 4000).Output -join "`n"
    $mac      =  ([regex]::Match($macRaw,'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}')).Value
    $ssid1    = ((Invoke-SSHCommand -SSHSession $session -Command $CmdGetSSID1 -TimeOut 3000).Output -join "`n").Trim()
    $ssid2    = ((Invoke-SSHCommand -SSHSession $session -Command $CmdGetSSID2 -TimeOut 3000).Output -join "`n").Trim()

    # Fill per-run summary row
    $sumRow.Identity   = $identity
    $sumRow.MAC        = $mac
    $sumRow.Version    = $ver
    $sumRow.SSID_wlan1 = $ssid1
    $sumRow.SSID_wlan2 = $ssid2
    $Summary.Add($sumRow)

    # Skip provisioning on non-wireless boxes
    $wl = ((Invoke-SSHCommand -SSHSession $session -Command $CmdHasWlan -TimeOut 2500).Output -join "`n").Trim()
    if ($wl -eq 'NOWL') {
      $ssidAction = "no-wireless"
      "$ip,$identity,$mac,$ver,$ssid1,$ssid2,`'true`',`'true`',$($conn.Mode),$ssidAction,$updAction," | Add-Content $LogFile
      continue
    }

    # Idempotent SSID check
    $chkOut = (Invoke-SSHCommand -SSHSession $session -Command $CmdChkSSID -TimeOut 3500).Output -join "`n"
    if ($chkOut -match 'PRESENT') {
      $ssidAction = "skipped"
    } else {
      $ssidAction = "provisioned"
      Invoke-SSHCommand -SSHSession $session -Command $CmdProvision | Out-Null
    }

    # Optional update to long-term
    if ($DoUpdate) {
      Invoke-SSHCommand -SSHSession $session -Command $CmdSetLT | Out-Null
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
      } else { $updAction = "up-to-date ($installed)" }
    }

    "$ip,$identity,$mac,$ver,$ssid1,$ssid2,`'true`',`'true`',$($conn.Mode),$ssidAction,$updAction," | Add-Content $LogFile
  } catch {
    $Summary.Add($sumRow)
    "$ip,$identity,$mac,$ver,$ssid1,$ssid2,`'true`',`'true`',$($conn.Mode),$ssidAction,$updAction,$($_.Exception.Message -replace ',',';')" | Add-Content $LogFile
  } finally {
    if ($session) { Remove-SSHSession -SSHSession $session | Out-Null }
  }
}

# Per-run summary of ALL ping-alive hosts (details filled if SSH succeeded)
$Summary | Export-Csv -Path $SummaryFile -NoTypeInformation -Encoding UTF8
Write-Host "Summary: $SummaryFile"
Write-Host "Log:     $LogFile"