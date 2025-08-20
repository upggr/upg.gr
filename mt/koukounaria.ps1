# koukounaria.ps1  —  scan/provision MikroTik CAPs (inline, no .rsc)
Import-Module Posh-SSH -ErrorAction Stop

# -------- CONFIG --------
$BaseNet   = "192.168.208."
$StartIP   = 100
$EndIP     = 165
$Username  = "admin"
$Password  = "is3rupgr.1821##"
$SSID      = "Koukounaria Guest 9"
$VlanId    = 10
$DoUpdate  = $true           # set $false to skip RouterOS update
# ------------------------

# RouterOS one-liners (safe on v6)
$CmdGetID      = ':put [/system identity get name]'
$CmdGetVer     = ':put [/system resource get version]'
# ether1 MAC if exists, else first enabled ethernet MAC
$CmdGetMacE1   = ':local i [/interface ethernet find where name="ether1"]; :if ([:len $i]>0) do={:put [/interface ethernet get $i mac-address]} else={:local e [/interface ethernet find where disabled=no]; :if ([:len $e]>0) do={:put ( [/interface ethernet get $e mac-address]->0 )} else={:put ""}}'
# SSIDs per radio (blank if radio missing)
$CmdGetSSID1   = ':if ([:len [/interface wireless find where name="wlan1"]]>0) do={:put [/interface wireless get wlan1 ssid]} else={:put ""}'
$CmdGetSSID2   = ':if ([:len [/interface wireless find where name="wlan2"]]>0) do={:put [/interface wireless get wlan2 ssid]} else={:put ""}'
# presence of any wireless interface
$CmdHasWlan    = ':if ([:len [/interface find where type~"wlan"]]>0) do={:put WL} else={:put NOWL}'
# check if our SSID exists (idempotent)
$CmdChkSSID    = ":if ([:len [/interface wireless find where ssid=`"$SSID`"]] > 0) do={:put PRESENT} else={:put ABSENT}"

# INLINE PROVISION (no .rsc) — disable CAP, reset radios, open SSID on both bands, VLAN 10 tagging, DHCP on ether1, bridge/VLAN config, reboot
$CmdProvision = @"
:put "=== starting inline provision ===";
# DECAP: fully remove CAP settings and disable CAPsMAN pkg if present
/interface wireless cap set enabled=no interfaces="" discovery-interfaces="" caps-man-addresses="" certificate="" static-virtual=no; :if ([:len [/system package find where name="caps-man"]]>0) do={/system package disable caps-man}; :do { /caps-man manager set enabled=no } on-error={}; /delay 1;
/interface wireless
:if ([:len [find where name="wlan1"]]>0) do={reset-configuration wlan1};
/delay 1;
:if ([:len [find where name="wlan2"]]>0) do={reset-configuration wlan2};

/interface wireless security-profiles
:if ([:len [find where name="guest_open"]]=0) do={add name=guest_open authentication-types="" unicast-ciphers="" group-ciphers="""};

/interface wireless
:if ([:len [find where name="wlan1"]]>0) do={set wlan1 mode=ap-bridge ssid="$SSID" security-profile=guest_open vlan-mode=use-tag vlan-id=$VlanId disabled=no};
:if ([:len [find where name="wlan2"]]>0) do={set wlan2 mode=ap-bridge ssid="$SSID" security-profile=guest_open vlan-mode=use-tag vlan-id=$VlanId disabled=no};

/ip dhcp-client
:if ([:len [find where interface="ether1"]]=0) do={add interface=ether1 disabled=no} else={set [find where interface="ether1"] disabled=no};

:local brId [/interface bridge find];
:local brName "";
:if ([:len $brId]>0) do={:set brName [/interface bridge get ($brId->0) name]} else={/interface bridge add name=bridge1; :set brName "bridge1"};

/interface bridge port
:if ([:len [/interface wireless find where name="wlan1"]]>0 && [:len [find where bridge=$brName interface="wlan1"]]=0) do={add bridge=$brName interface=wlan1};
:if ([:len [/interface wireless find where name="wlan2"]]>0 && [:len [find where bridge=$brName interface="wlan2"]]=0) do={add bridge=$brName interface=wlan2};

:local tagged "$brName,ether1";
:if ([:len [/interface wireless find where name="wlan1"]]>0) do={:set tagged "$tagged,wlan1"};
:if ([:len [/interface wireless find where name="wlan2"]]>0) do={:set tagged "$tagged,wlan2"};

/interface bridge vlan
:if ([:len [find where bridge=$brName vlan-ids=$VlanId]] = 0) do={add bridge=$brName vlan-ids=$VlanId tagged=$tagged} else={set [find where bridge=$brName vlan-ids=$VlanId] tagged=$tagged};
/interface bridge set [find where name=$brName] vlan-filtering=yes;

:put "=== inline provision complete; rebooting ===";
/system reboot without-prompt=yes;
"@

# Update helpers
$CmdSetLT       = '/system package update set channel=long-term'
$CmdCheckUpd    = '/system package update check-for-updates'
$CmdGetInstVer  = ':put [/system package update get installed-version]'
$CmdGetLatest   = ':put [/system package update get latest-version]'

# ---- helpers ----
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

function Wait-ForHost {
  param([string]$ip,[int]$timeoutSec=240)
  $sw=[Diagnostics.Stopwatch]::StartNew()
  while($sw.Elapsed.TotalSeconds -lt $timeoutSec){
    & ping.exe -n 1 -w 800 $ip 1>$null 2>$null
    if($LASTEXITCODE -eq 0){ return $true }
    Start-Sleep -Seconds 2
  }
  return $false
}

function Reconnect-SSH {
  param([string]$ip,[string]$user,[string]$pass)
  $cred = New-Object PSCredential ($user,(ConvertTo-SecureString $pass -AsPlainText -Force))
  try { return (New-SSHSession -ComputerName $ip -Credential $cred -AcceptKey -ErrorAction Stop) } catch { return $null }
}

# ---- files ----
$LogFile = ".\deploy-log.csv"
if (-not (Test-Path $LogFile)) {
  "IP,Identity,MAC,Version,SSID_wlan1,SSID_wlan2,Reachable,P22Open,AuthMode,SSIDAction,UpdateAction,Note" | Out-File -Encoding ascii $LogFile
}
$ts = Get-Date -Format "yyyyMMdd-HHmmss"
$SummaryFile = ".\deploy-summary-$ts.csv"
$Summary = New-Object System.Collections.Generic.List[object]

# ---- main loop ----
for ($i=$StartIP; $i -le $EndIP; $i++) {
  $ip = "$BaseNet$i"
  Write-Host "[$ip] Ping check..."
  if (-not (Ping-Fast $ip)) { "$ip,,,,,`'false`',`'false`',,,-,no ping" | Add-Content $LogFile; continue }

  $sumRow = [PSCustomObject]@{ IP=$ip; Identity=""; MAC=""; Version=""; SSID_wlan1=""; SSID_wlan2="" }

  if (-not (Port22-Open $ip)) {
    "$ip,,,,,`'true`',`'false`',,,-,ssh closed" | Add-Content $LogFile; continue
  }

  $conn = Try-SSH $ip $Username $Password
  if (-not $conn) {
    "$ip,,,,,`'true`',`'true`',,,-,ssh auth failed" | Add-Content $LogFile; continue
  }

  $session = $conn.Session
  $identity=""; $mac=""; $ver=""; $ssid1=""; $ssid2=""; $ssidAction="n/a"; $updAction="n/a"

  try {
    # If we logged in with NO password, set it now
    if ($conn.Mode -eq "nopass") {
      $CmdSetPwd = "/user set [find name=$Username] password=`"$Password`""
      Invoke-SSHCommand -SSHSession $session -Command $CmdSetPwd | Out-Null
      Write-Host "[$ip] Password set for '$Username'." -ForegroundColor Magenta
    }

    # Collect details
    $identity = ((Invoke-SSHCommand -SSHSession $session -Command $CmdGetID  -TimeOut 4000).Output -join "`n").Trim()
    $ver      = ((Invoke-SSHCommand -SSHSession $session -Command $CmdGetVer -TimeOut 4000).Output -join "`n").Trim()
    $macRaw   =  (Invoke-SSHCommand -SSHSession $session -Command $CmdGetMacE1 -TimeOut 4000).Output -join "`n"
    $mac      =  ([regex]::Match($macRaw,'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}')).Value
    $ssid1    = ((Invoke-SSHCommand -SSHSession $session -Command $CmdGetSSID1 -TimeOut 2500).Output -join "`n").Trim()
    $ssid2    = ((Invoke-SSHCommand -SSHSession $session -Command $CmdGetSSID2 -TimeOut 2500).Output -join "`n").Trim()

    $sumRow.Identity   = $identity; $sumRow.MAC=$mac; $sumRow.Version=$ver; $sumRow.SSID_wlan1=$ssid1; $sumRow.SSID_wlan2=$ssid2

    $didProvision = $false

    # Skip provisioning on boxes with no wireless
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
      $didProvision = $true
      Invoke-SSHCommand -SSHSession $session -Command $CmdProvision | Out-Null
      # device will reboot; drop the current session
      try { Remove-SSHSession -SSHSession $session | Out-Null } catch {}
      # wait for it to come back and reconnect
      if (Wait-ForHost $ip 240) {
        $re = Reconnect-SSH $ip $Username $Password
        if ($re -ne $null) {
          $session = $re
          # re-read SSIDs and enforce if needed
          $ssid1 = ((Invoke-SSHCommand -SSHSession $session -Command $CmdGetSSID1 -TimeOut 4000).Output -join "`n").Trim()
          $ssid2 = ((Invoke-SSHCommand -SSHSession $session -Command $CmdGetSSID2 -TimeOut 4000).Output -join "`n").Trim()
          if (($ssid1 -ne $SSID -and $ssid1 -ne "") -or ($ssid2 -ne $SSID -and $ssid2 -ne "")) {
            $cmdEnforce = @"
/interface wireless set [find where name="wlan1"] mode=ap-bridge ssid="$SSID" security-profile=guest_open vlan-mode=use-tag vlan-id=$VlanId disabled=no;
/interface wireless set [find where name="wlan2"] mode=ap-bridge ssid="$SSID" security-profile=guest_open vlan-mode=use-tag vlan-id=$VlanId disabled=no;
"@
            Invoke-SSHCommand -SSHSession $session -Command $cmdEnforce | Out-Null
            $ssid1 = ((Invoke-SSHCommand -SSHSession $session -Command $CmdGetSSID1 -TimeOut 4000).Output -join "`n").Trim()
            $ssid2 = ((Invoke-SSHCommand -SSHSession $session -Command $CmdGetSSID2 -TimeOut 4000).Output -join "`n").Trim()
          }
          $ssidAction = "provisioned+verified"
        } else {
          $ssidAction = "provisioned+reconnect-failed"
        }
      } else {
        $ssidAction = "provisioned+timeout"
      }
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

    $Summary.Add($sumRow)
    "$ip,$identity,$mac,$ver,$ssid1,$ssid2,`'true`',`'true`',$($conn.Mode),$ssidAction,$updAction," | Add-Content $LogFile
  } catch {
    "$ip,$identity,$mac,$ver,$ssid1,$ssid2,`'true`',`'true`',$($conn.Mode),$ssidAction,$updAction,$($_.Exception.Message -replace ',',';')" | Add-Content $LogFile
  } finally {
    if ($session) { Remove-SSHSession -SSHSession $session | Out-Null }
  }
}

# Per-run summary of ALL ping-alive hosts
$Summary | Export-Csv -Path $SummaryFile -NoTypeInformation -Encoding UTF8
Write-Host "Summary: $SummaryFile"
Write-Host "Log:     $LogFile"