# koukounaria.ps1 — scan & FORCE-config MikroTik APs (no .rsc)
Import-Module Posh-SSH -ErrorAction Stop

# ======== USER CONFIG ========
$BaseNet        = "192.168.208."
$StartIP        = 163        # inclusive
$EndIP          = 163       # inclusive
$Username       = "admin"
$Password       = "is3rupgr.1821##"   # will be set if device has no password
$SSID           = "Koukounaria Hotel Guest"
$VlanId         = 10
$UpdateChannel  = "long-term"  # change to "stable" if you want the stable channel
$DoUpdate       = $true
# =============================

# ---------- helpers ----------
# Legacy SSH algorithms for old RouterOS (v6.x)
$KexLegacy     = @('diffie-hellman-group1-sha1','diffie-hellman-group14-sha1')
$MacLegacy     = @('hmac-sha1','hmac-md5')
$CipherLegacy  = @('aes128-cbc','aes192-cbc','aes256-cbc','3des-cbc','aes128-ctr','aes256-ctr')
$HostKeyLegacy = @('ssh-rsa','ssh-dss')

function Ping-Fast($ip){ & ping.exe -n 1 -w 700 $ip 1>$null 2>$null; return ($LASTEXITCODE -eq 0) }
function Port22-Open($ip){ try { Test-NetConnection -ComputerName $ip -Port 22 -InformationLevel Quiet } catch { $false } }
function New-Cred($user,$pass){ New-Object PSCredential ($user,(ConvertTo-SecureString $pass -AsPlainText -Force)) }

function Connect-MT {
  param([string]$ip,[string]$user,[string]$pass)
  # 1) Try with the defined password
  try {
    $credPwd = New-Cred $user $pass
    $s = New-SSHSession -ComputerName $ip -Credential $credPwd -AcceptKey -ConnectionTimeout 15000 -ErrorAction Stop
    return @{ Session=$s; Mode='password' }
  } catch {
    $msg = $_.Exception.Message
    if ($msg -match 'expired|must be changed|change.*password') { return @{ Session=$null; Mode='expired'; Error=$msg } }
  }
  # 2) Try with no password
  try {
    $credNone = New-Cred $user ""
    $s = New-SSHSession -ComputerName $ip -Credential $credNone -AcceptKey -ConnectionTimeout 15000 -ErrorAction Stop
    return @{ Session=$s; Mode='nopass' }
  } catch {
    return $null
  }
}

function Wait-ForHost { param([string]$ip,[int]$timeoutSec=300)
  $sw=[Diagnostics.Stopwatch]::StartNew()
  while($sw.Elapsed.TotalSeconds -lt $timeoutSec){ & ping.exe -n 1 -w 900 $ip 1>$null 2>$null; if($LASTEXITCODE -eq 0){ return $true } Start-Sleep -Seconds 2 }
  return $false
}

function Reconnect-SSH { param([string]$ip,[string]$user,[string]$pass)
  try { New-SSHSession -ComputerName $ip -Credential (New-Cred $user $pass) -AcceptKey -ConnectionTimeout 15000 -ErrorAction Stop } catch { $null }
}

# ---- Step execution helper with feedback ----
function Exec-Step {
  param(
    $session,
    [string]$ip,
    [string]$cmd,
    [string]$desc,
    [switch]$ShowOut
  )
  Write-Host "$ip → $desc..." -ForegroundColor Gray
  try {
    $r = Invoke-SSHCommand -SSHSession $session -Command $cmd -TimeOut 20000 -ErrorAction Stop
    $out = ($r.Output -join "").Trim()
    $err = ($r.Error  -join "").Trim()
    if ($err) { Write-Host "$ip → FAIL: $desc :: $err" -ForegroundColor Red; return @{ ok=$false; out=$out; err=$err } }
    Write-Host "$ip → OK: $desc" -ForegroundColor Green
    if ($ShowOut -and $out) { Write-Host ("$ip ← $out") -ForegroundColor DarkGray }
    return @{ ok=$true; out=$out; err='' }
  } catch {
    $em = $_.Exception.Message
    Write-Host "$ip → ERROR: $desc :: $em" -ForegroundColor Red
    return @{ ok=$false; out=''; err=$em }
  }
}

# Prints VLAN/WLAN/DHCP checks to the console for a given session/IP/vlanId
# Prints VLAN/WLAN/DHCP checks to the console for a given session/IP/vlanId

function Dump-BridgeState {
  param($session,[string]$ip,[string]$label='STATE')
  Write-Host "$ip ⇒ [$label] Bridge/Port/VLAN state" -ForegroundColor DarkCyan
  Exec-Step -session $session -ip $ip -desc 'bridge print' -cmd '/interface bridge print detail' -ShowOut
  Exec-Step -session $session -ip $ip -desc 'bridge port print' -cmd '/interface bridge port print detail' -ShowOut
  Exec-Step -session $session -ip $ip -desc 'bridge vlan print' -cmd '/interface bridge vlan print detail' -ShowOut
}

# Probe DHCP by attaching a temp VLAN10 interface to the bridge and probing for DHCP lease
function Probe-DHCP-OnWlan {
  param($session,[string]$ip,[string]$bridge='bridge1',[int]$timeoutSec=20)
  $status=''; $addr=''
  try {
    Invoke-SSHCommand -SSHSession $session -Command '/ip dhcp-client remove [find where comment=probe]' | Out-Null
    Invoke-SSHCommand -SSHSession $session -Command '/interface vlan remove [find where name=probe_vlan10]' | Out-Null
    Invoke-SSHCommand -SSHSession $session -Command "/interface vlan add name=probe_vlan10 interface=$bridge vlan-id=$VlanId" | Out-Null
    Invoke-SSHCommand -SSHSession $session -Command '/ip dhcp-client add interface=probe_vlan10 add-default-route=no use-peer-dns=no use-peer-ntp=no disabled=no comment=probe' | Out-Null
    $stCmd = ':local id [/ip dhcp-client find where interface=probe_vlan10 comment=probe]; :if ([:len $id]>0) do={:put [/ip dhcp-client get $id status]} else={:put none}'
    $adCmd = ':local id [/ip dhcp-client find where interface=probe_vlan10 comment=probe]; :put [/ip dhcp-client get $id address]'
    $sw=[Diagnostics.Stopwatch]::StartNew()
    while($sw.Elapsed.TotalSeconds -lt $timeoutSec){
      $status = ((Invoke-SSHCommand -SSHSession $session -Command $stCmd).Output -join '').Trim()
      if($status -eq 'bound'){ $addr = ((Invoke-SSHCommand -SSHSession $session -Command $adCmd).Output -join '').Trim(); break }
      Start-Sleep -Milliseconds 800
    }
  } catch {
    $status = "error: $($_.Exception.Message)"
  } finally {
    try { Invoke-SSHCommand -SSHSession $session -Command '/ip dhcp-client remove [find where comment=probe]' | Out-Null } catch {}
    try { Invoke-SSHCommand -SSHSession $session -Command '/interface vlan remove [find where name=probe_vlan10]' | Out-Null } catch {}
  }

  if($status -eq 'bound' -and $addr){ Write-Host "$ip → [DHCP-PROBE] VLAN$VlanId bound $addr [OK]" -ForegroundColor Green; return $addr }
  elseif($status -in 'searching','requesting'){ Write-Host "$ip → [DHCP-PROBE] VLAN$VlanId $status [WARN]" -ForegroundColor Yellow; return '' }
  elseif($status -eq 'none'){ Write-Host "$ip → [DHCP-PROBE] VLAN$VlanId probe not found [WARN]" -ForegroundColor Yellow; return '' }
  elseif($status){ Write-Host "$ip → [DHCP-PROBE] VLAN$VlanId $status [FAIL]" -ForegroundColor Red; return '' }
  else { Write-Host "$ip → [DHCP-PROBE] VLAN$VlanId unknown [FAIL]" -ForegroundColor Red; return '' }
}

function Print-NetworkChecks {
  param($session,[string]$ip,[int]$vlanId)
  try {
    $br = ((Invoke-SSHCommand -SSHSession $session -Command ':put [/interface bridge get [find] name]').Output -join '').Trim(); if(-not $br){$br='bridge1'}

    # VLAN filtering state
    $bf = ((Invoke-SSHCommand -SSHSession $session -Command (":put [/interface bridge get $br vlan-filtering]")).Output -join '').Trim()
    Write-Host "$ip → [CHECK] Bridge $br vlan-filtering=$bf" -ForegroundColor DarkCyan

    # VLAN table entry for vlanId
    $cmdVlanTpl = ':local id [/interface bridge vlan find where bridge=[BR] vlan-ids=[VID]]; :if ([:len $id]>0) do={:put ("present tagged=".[:tostr [/interface bridge vlan get $id tagged]]." untagged=".[:tostr [/interface bridge vlan get $id untagged]])} else={:put "missing"}'
    $cmdVlan = $cmdVlanTpl.Replace('[BR]',$br).Replace('[VID]',$vlanId)
    $vlanInfo = ((Invoke-SSHCommand -SSHSession $session -Command $cmdVlan).Output -join '').Trim()
    if ($vlanInfo -match '^present') { Write-Host ("$ip → [CHECK] VLAN {0} on {1}: {2} [OK]" -f $vlanId,$br,$vlanInfo) -ForegroundColor Green } else { Write-Host ("$ip → [CHECK] VLAN {0}: missing [FAIL]" -f $vlanId) -ForegroundColor Red }

    # PVID on wlan ports
    foreach($w in 'wlan1','wlan2'){
      $pvidTpl = ':local id [/interface bridge port find where interface=[W]]; :if ([:len $id]>0) do={:put [/interface bridge port get $id pvid]} else={:put "na"}'
      $pvidCmd = $pvidTpl.Replace('[W]',$w)
      $pvid = ((Invoke-SSHCommand -SSHSession $session -Command $pvidCmd).Output -join '').Trim()
      if($pvid -eq 'na'){ Write-Host "$ip → [CHECK] $w in bridge: not present [WARN]" -ForegroundColor Yellow }
      elseif([int]$pvid -eq $vlanId){ Write-Host "$ip → [CHECK] $w pvid=$pvid [OK]" -ForegroundColor Green }
      else{ Write-Host "$ip → [CHECK] $w pvid=$pvid (expected $vlanId) [FAIL]" -ForegroundColor Red }
    }

    # Wireless SSID/disabled/running
    foreach($w in 'wlan1','wlan2'){
      $ssid = ((Invoke-SSHCommand -SSHSession $session -Command (":put [/interface wireless get $w ssid]")).Output -join '').Trim()
      $dis  = ((Invoke-SSHCommand -SSHSession $session -Command (":put [/interface wireless get $w disabled]")).Output -join '').Trim()
      $run  = ((Invoke-SSHCommand -SSHSession $session -Command (":put [/interface wireless get $w running]")).Output -join '').Trim()
      if($ssid){
        $ok = ($dis -eq 'false' -and $run -eq 'true')
        $st = if($ok){'OK'} else {'WARN'}
        $color = if($ok){'Green'} else {'Yellow'}
        Write-Host ("$ip → [CHECK] {0}: ssid='{1}' disabled={2} running={3} [{4}]" -f $w,$ssid,$dis,$run,$st) -ForegroundColor $color
      }
    }

    # DHCP client on mgmt.<vlanId>
    $cmdDhcpTpl = ':local id [/ip dhcp-client find where interface="mgmt.[VID]"]; :if ([:len $id]>0) do={:put ( [/ip dhcp-client get $id status]." ".[/ip dhcp-client get $id address])} else={:put "none"}'
    $cmdDhcp = $cmdDhcpTpl.Replace('[VID]',$vlanId)
    $dhcpInfo = ((Invoke-SSHCommand -SSHSession $session -Command $cmdDhcp).Output -join '').Trim()
    if($dhcpInfo -ne 'none'){
      if($dhcpInfo -match '^bound'){ Write-Host "$ip → [CHECK] DHCP client on mgmt.${vlanId}: $dhcpInfo [OK]" -ForegroundColor Green }
      else{ Write-Host "$ip → [CHECK] DHCP client on mgmt.${vlanId}: $dhcpInfo [WARN]" -ForegroundColor Yellow }
    } else {
      Write-Host "$ip → [CHECK] DHCP client on mgmt.${vlanId}: none [INFO]" -ForegroundColor DarkGray
    }
  } catch {
    Write-Host "$ip → [CHECK] error: $($_.Exception.Message)" -ForegroundColor Red
  }
}

# ---- RouterOS one-liners ----
$CmdGetID    = ':put [/system identity get name]'
$CmdGetVer   = ':put [/system resource get version]'
$CmdHasWlan  = ':put ([:len [/interface find where type~"wlan"]])'
$CmdSSID1    = ':put [/interface wireless get wlan1 ssid]'
$CmdSSID2    = ':put [/interface wireless get wlan2 ssid]'
$CmdDis1     = ':put [/interface wireless get wlan1 disabled]'
$CmdDis2     = ':put [/interface wireless get wlan2 disabled]'
$CmdCapOn    = ':put [/interface wireless cap get enabled]'
$CmdWlanCnt  = ':put ([:len [/interface wireless find where name~"wlan"]])'

# ---- FORCE-config blocks (always apply) ----
$CmdDecap = @"
/interface wireless cap set enabled=no interfaces="" discovery-interfaces="" caps-man-addresses="" certificate="" static-virtual=no
:do { /caps-man manager set enabled=no } on-error={}
:do { /system package disable caps-man } on-error={}
"@

$CmdNukeCapsMan = @"
# wipe CAPsMAN state completely (safe if absent)
:do { /caps-man manager set enabled=no } on-error={}
:do { /caps-man provisioning remove [find] } on-error={}
:do { /caps-man configuration remove [find] } on-error={}
:do { /caps-man datapath remove [find] } on-error={}
:do { /caps-man security remove [find] } on-error={}
:do { /caps-man channel remove [find] } on-error={}
:do { /caps-man rates remove [find] } on-error={}
:do { /caps-man access-list remove [find] } on-error={}
"@

# (unused)
$CmdForceWireless = @"
# Minimal explicit apply: set SSID and enable radios (no mass disable/reset)
/interface wireless
:do { set wlan1 mode=ap-bridge ssid="$SSID" disabled=no } on-error={}
:do { enable wlan1 } on-error={}
:do { set wlan2 mode=ap-bridge ssid="$SSID" disabled=no } on-error={}
:do { enable wlan2 } on-error={}
"@

# legacy (unused)
$CmdNet = @'
/interface bridge remove [find where name~"^bridge" and name!="bridge1"]
# Ensure bridge exists
:local brId [/interface bridge find]; :local brName ""; :if ([:len $brId]>0) do={:set brName [/interface bridge get ($brId->0) name]} else={/interface bridge add name=bridge1; :set brName "bridge1"}

# Add ALL ethernet ports to the bridge
/interface bridge port
:foreach e in=[/interface ethernet find] do={ :local n [/interface ethernet get $e name]; :if ([:len [find where bridge=$brName interface=$n]]=0) do={ add bridge=$brName interface=$n } }

# Add WLANs to the bridge if present
:if ([:len [/interface wireless find where name="wlan1"]]>0 && [:len [find where bridge=$brName interface="wlan1"]]=0) do={ add bridge=$brName interface=wlan1 }
:if ([:len [/interface wireless find where name="wlan2"]]>0 && [:len [find where bridge=$brName interface="wlan2"]]=0) do={ add bridge=$brName interface=wlan2 }

# Ensure PVID on WLAN ports (access)
/interface bridge port
:if ([:len [/interface wireless find where name="wlan1"]]>0) do={
  :if ([:len [find where bridge=$brName interface="wlan1"]]=0) do={ add bridge=$brName interface=wlan1 pvid=__VID__ } else={ set [find where bridge=$brName interface="wlan1"] pvid=__VID__ }
}
:if ([:len [/interface wireless find where name="wlan2"]]>0) do={
  :if ([:len [find where bridge=$brName interface="wlan2"]]=0) do={ add bridge=$brName interface=wlan2 pvid=__VID__ } else={ set [find where bridge=$brName interface="wlan2"] pvid=__VID__ }
}

# VLAN (configured ID): bridge+ethernet = tagged (trunk), WLANs = untagged (access)
:local tagged "$brName"
:foreach e in=[/interface ethernet find] do={ :set tagged "$tagged,[:tostr [/interface ethernet get $e name]]" }
:local untagged ""
:if ([:len [/interface wireless find where name="wlan1"]]>0) do={ :set untagged "wlan1" }
:if ([:len [/interface wireless find where name="wlan2"]]>0) do={ :if ([:len $untagged]>0) do={ :set untagged "$untagged,wlan2" } else={ :set untagged "wlan2" } }

/interface bridge vlan
:if ([:len [find where bridge=$brName vlan-ids=__VID__]]=0) do={ add bridge=$brName vlan-ids=__VID__ tagged=$tagged untagged=$untagged } else={ set [find where bridge=$brName vlan-ids=__VID__] tagged=$tagged untagged=$untagged }

/interface bridge set [find where name=$brName] vlan-filtering=yes

# Management on VLAN: create VLAN interface on bridge and move DHCP client there
/interface vlan
:if ([:len [find where name="mgmt.__VID__"]]=0) do={ add name="mgmt.__VID__" interface=$brName vlan-id=__VID__ } else={ set [find where name="mgmt.__VID__"] interface=$brName vlan-id=__VID__ }

/ip dhcp-client
:foreach i in=[find] do={ remove $i }
:add interface="mgmt.__VID__" disabled=no
'@

$CmdReboot = '/system reboot without-prompt=yes'

function Update-MT {
  param($session,[string]$channel,[string]$ip)
  try {
    Invoke-SSHCommand -SSHSession $session -Command "/system package update set channel=$channel" | Out-Null
    Invoke-SSHCommand -SSHSession $session -Command '/system package update check-for-updates' | Out-Null
    $installed = (Invoke-SSHCommand -SSHSession $session -Command ':put [/system package update get installed-version]').Output -join ""
    $latest    = (Invoke-SSHCommand -SSHSession $session -Command ':put [/system package update get latest-version]').Output -join ""
    if ($latest -and $installed -and ($latest.Trim() -ne $installed.Trim())) {
      try { Invoke-SSHCommand -SSHSession $session -Command '/system package update download-install' -TimeOut 180000 | Out-Null }
      catch {
        Invoke-SSHCommand -SSHSession $session -Command '/system package update download' -TimeOut 180000 | Out-Null
        Invoke-SSHCommand -SSHSession $session -Command $CmdReboot | Out-Null
      }
      try { Remove-SSHSession -SSHSession $session | Out-Null } catch {}
      if (Wait-ForHost $ip 300) { return (Reconnect-SSH $ip $Username $Password) } else { return $null }
    } else { return $session }
  } catch { return $session }
}

function Force-Config {
  param($session,[string]$ip)
  Write-Host "$ip → Starting forced configuration..." -ForegroundColor Magenta
  if ($null -eq $session) { return @{ssid1=''; ssid2=''; status='forced-no-session'} }
  # Immediately and explicitly disable CAP mode and CAPsMAN manager before any SSID or bridge/VLAN operations
  Exec-Step -session $session -ip $ip -cmd '/interface wireless cap set enabled=no' -desc 'Disable CAP mode' | Out-Null
  Exec-Step -session $session -ip $ip -cmd '/caps-man manager set enabled=no' -desc 'Disable CAPsMAN manager' | Out-Null
  # Discovery feedback: CAP mode and wireless count
  $capState0 = ((Invoke-SSHCommand -SSHSession $session -Command $CmdCapOn).Output -join '').Trim()
  $capMsg0 = if ($capState0 -eq 'true') { 'ON' } else { 'OFF' }
  $wl0 = [int](((Invoke-SSHCommand -SSHSession $session -Command $CmdWlanCnt).Output -join '').Trim())
  Write-Host ("$ip → (discovery) CAP mode {0}, wireless interface(s): {1}" -f $capMsg0, $wl0) -ForegroundColor DarkCyan
  # remove CAP/caps-man, wipe wifi, bridge/trunk VLAN, reboot, verify loop
  if (-not (Exec-Step -session $session -ip $ip -cmd $CmdDecap        -desc 'Disabling CAPsMAN and CAP').ok) { return @{ssid1=''; ssid2=''; status='caps-disable-failed'; session=$session} }
  if (-not (Exec-Step -session $session -ip $ip -cmd $CmdNukeCapsMan   -desc 'Wiping CAPsMAN state').ok)      { return @{ssid1=''; ssid2=''; status='caps-wipe-failed';   session=$session} }
  if (-not (Exec-Step -session $session -ip $ip -cmd "/interface wireless set [find default-name=wlan1] ssid=`"$SSID`" disabled=no" -desc 'Set SSID on wlan1').ok) { Write-Host "$ip → note: wlan1 may not exist" -ForegroundColor DarkYellow }
  if (-not (Exec-Step -session $session -ip $ip -cmd "/interface wireless enable [find default-name=wlan1]" -desc 'Enable wlan1').ok) { Write-Host "$ip → note: enable wlan1 failed/absent" -ForegroundColor DarkYellow }
  if (-not (Exec-Step -session $session -ip $ip -cmd "/interface wireless set [find default-name=wlan2] ssid=`"$SSID`" disabled=no" -desc 'Set SSID on wlan2').ok) { Write-Host "$ip → note: wlan2 may not exist" -ForegroundColor DarkYellow }
  if (-not (Exec-Step -session $session -ip $ip -cmd "/interface wireless enable [find default-name=wlan2]" -desc 'Enable wlan2').ok) { Write-Host "$ip → note: enable wlan2 failed/absent" -ForegroundColor DarkYellow }
  # --- PRE state dump ---
  Dump-BridgeState -session $session -ip $ip -label 'PRE'

  # Ensure bridge1 exists
  if (-not (Exec-Step -session $session -ip $ip -cmd ':do {/interface bridge add name=bridge1} on-error={}' -desc 'ensure bridge1').ok) { return @{ssid1=''; ssid2=''; status='bridge-add-failed'; session=$session} }

  # Add ports (idempotent) and set WLAN PVIDs
  if (-not (Exec-Step -session $session -ip $ip -cmd ":do {/interface bridge port add bridge=bridge1 interface=wlan1 pvid=$VlanId} on-error={}" -desc 'add wlan1 to bridge1 pvid' ).ok) { Write-Host "$ip → note: wlan1 add/pvid may have failed" -ForegroundColor Yellow }
  if (-not (Exec-Step -session $session -ip $ip -cmd ":do {/interface bridge port add bridge=bridge1 interface=wlan2 pvid=$VlanId} on-error={}" -desc 'add wlan2 to bridge1 pvid' ).ok) { Write-Host "$ip → note: wlan2 add/pvid may have failed" -ForegroundColor Yellow }
  if (-not (Exec-Step -session $session -ip $ip -cmd ':do {/interface bridge port add bridge=bridge1 interface=ether1} on-error={}' -desc 'add ether1 to bridge1 (trunk)').ok) { Write-Host "$ip → note: ether1 add may have failed" -ForegroundColor Yellow }

  # Create/refresh VLAN row and enable filtering
  if (-not (Exec-Step -session $session -ip $ip -cmd "/interface bridge vlan add bridge=bridge1 vlan-ids=$VlanId tagged=bridge1,ether1 untagged=wlan1,wlan2" -desc 'add VLAN row (10)').ok) { Write-Host "$ip → VLAN add may already exist; trying set" -ForegroundColor Yellow; Exec-Step -session $session -ip $ip -cmd "/interface bridge vlan set [find where bridge=bridge1 vlan-ids=$VlanId] tagged=bridge1,ether1 untagged=wlan1,wlan2" -desc 'set VLAN row (10)' | Out-Null }
  if (-not (Exec-Step -session $session -ip $ip -cmd '/interface bridge set [find where name=bridge1] vlan-filtering=yes' -desc 'enable vlan-filtering').ok) { return @{ssid1=''; ssid2=''; status='vlan-filtering-failed'; session=$session} }
  # Ensure VLAN 1 does not carry untagged ether1 on the bridge (keep trunk clean)
  Exec-Step -session $session -ip $ip -cmd '/interface bridge vlan set [find where bridge=bridge1 vlan-ids=1] tagged=bridge1,ether1 untagged=' -desc 'fix VLAN1 (untagged empty)' | Out-Null

  # --- POST state dump ---
  Dump-BridgeState -session $session -ip $ip -label 'POST'

  # Visibility: show VLAN/port/wireless/DHCP checks
  Print-NetworkChecks -session $session -ip $ip -vlanId $VlanId

  # Probe DHCP on WLANs to emulate a client getting IP on VLAN $VlanId
Probe-DHCP-OnWlan -session $session -ip $ip -bridge 'bridge1'

  # Pre-check: ensure SSID + radios enabled BEFORE reboot, forcibly apply correct SSID and VLANs and forcibly disable CAPsMAN
  Write-Host "$ip → Forcing SSID/VLAN settings and disabling CAPsMAN before reboot..." -ForegroundColor Yellow
  $enforceCmd = @"
'; :do {
  /interface wireless cap disable;
  /interface wireless enable wlan1,wlan2;
  /interface wireless set wlan1 ssid="Koukounaria Guest 9";
  /interface wireless set wlan2 ssid="Koukounaria Guest 9";
  /interface bridge port set [find interface=wlan1] pvid=10;
  /interface bridge port set [find interface=wlan2] pvid=10;
} on-error={:put "=== ERROR applying SSID/VLAN settings ==="}
"@
  $enfResult = Exec-Step -session $session -ip $ip -cmd $enforceCmd -desc 'Force-disable CAPsMAN, enable WLANs, set SSID/VLAN'
  Start-Sleep -Seconds 3
  # Re-read to check
  $pre_s1 = ((Invoke-SSHCommand -SSHSession $session -Command $CmdSSID1 -TimeOut 3000).Output -join "").Trim()
  $pre_s2 = ((Invoke-SSHCommand -SSHSession $session -Command $CmdSSID2 -TimeOut 3000).Output -join "").Trim()
  $pre_d1 = ((Invoke-SSHCommand -SSHSession $session -Command $CmdDis1  -TimeOut 3000).Output -join "").Trim()
  $pre_d2 = ((Invoke-SSHCommand -SSHSession $session -Command $CmdDis2  -TimeOut 3000).Output -join "").Trim()
  $pre_ok1 = (($pre_s1 -eq "Koukounaria Guest 9" -and $pre_d1 -eq 'false') -or ($pre_s1 -eq '' -and $pre_d1 -eq 'true'))
  $pre_ok2 = (($pre_s2 -eq "Koukounaria Guest 9" -and $pre_d2 -eq 'false') -or ($pre_s2 -eq '' -and $pre_d2 -eq 'true'))
  if (-not ($pre_ok1 -or $pre_ok2)) {
    Write-Host ("$ip → ERROR: SSID/VLAN not applied; wlan1='{0}' disabled={1} wlan2='{2}' disabled={3}" -f $pre_s1,$pre_d1,$pre_s2,$pre_d2) -ForegroundColor Red
    return @{ssid1=$pre_s1; ssid2=$pre_s2; status='apply-failed'; session=$session}
  }

  # Final read-back before connectivity test
  $final1 = ((Invoke-SSHCommand -SSHSession $session -Command $CmdSSID1).Output -join "").Trim()
  $final2 = ((Invoke-SSHCommand -SSHSession $session -Command $CmdSSID2).Output -join "").Trim()
  $d1f = ((Invoke-SSHCommand -SSHSession $session -Command $CmdDis1).Output -join "").Trim()
  $d2f = ((Invoke-SSHCommand -SSHSession $session -Command $CmdDis2).Output -join "").Trim()
  $applied1 = (($final1 -eq $SSID -and $d1f -eq 'false') -or ($final1 -eq '' -and $d1f -eq 'true'))
  $applied2 = (($final2 -eq $SSID -and $d2f -eq 'false') -or ($final2 -eq '' -and $d2f -eq 'true'))
  if (-not ($applied1 -or $applied2)) {
    Write-Host ("$ip → Verification FAILED before ping (wlan1='{0}' disabled={1}, wlan2='{2}' disabled={3})" -f $final1,$d1f,$final2,$d2f) -ForegroundColor Red
    return @{ssid1=$final1; ssid2=$final2; status='verify-failed'; session=$session}
  }

  # WLAN internet test (ping 1.1.1.1 from wlan1/2)
  Write-Host "$ip → Testing internet from WLAN (1.1.1.1)..." -ForegroundColor Gray
  $okWlan = $false
  try {
    $p1 = ((Invoke-SSHCommand -SSHSession $session -Command ':put [/ping 1.1.1.1 interface=wlan1 count=3 interval=1s]')).Output -join ""; if ($p1 -match 'received') { $okWlan = $true }
  } catch {}
  try {
    $p2 = ((Invoke-SSHCommand -SSHSession $session -Command ':put [/ping 1.1.1.1 interface=wlan2 count=3 interval=1s]')).Output -join ""; if ($p2 -match 'received') { $okWlan = $true }
  } catch {}
  if (-not $okWlan) {
    Write-Host "$ip → ERROR: WLAN cannot reach internet" -ForegroundColor Red
    return @{ssid1=$final1; ssid2=$final2; status='wlan-no-internet'; session=$session}
  }
  Write-Host "$ip → WLAN internet OK" -ForegroundColor DarkGreen
  return @{ssid1=$final1; ssid2=$final2; status='ready'; session=$session}
}

# --------- files ---------
$LogFile = "./deploy-log.csv"
if (-not (Test-Path $LogFile)) { "IP,Identity,Version,SSID1,SSID2,Action,Note" | Out-File -Encoding ascii $LogFile }
$ts = Get-Date -Format "yyyyMMdd-HHmmss"
$SummaryFile = "./deploy-summary-$ts.csv"
"IP,Identity,MAC,Version,SSID_wlan1,SSID_wlan2" | Out-File -Encoding ascii $SummaryFile

# ------------- main -------------
for($i=$StartIP; $i -le $EndIP; $i++){
  $ip = "$BaseNet$i"
  Write-Host "[$ip] scanning..." -ForegroundColor Cyan
  if (-not (Ping-Fast $ip)) { "${ip},,,,,'skip','no ping'" | Add-Content $LogFile; continue }
  if (-not (Port22-Open $ip)) { "${ip},,,,,'skip','ssh closed'" | Add-Content $LogFile; continue }

  $conn = Connect-MT $ip $Username $Password
  if ($conn) { Write-Host "$ip → SSH OK ($($conn.Mode))" -ForegroundColor Green }
  if ($null -eq $conn) { "${ip},,,,,'skip','ssh auth failed'" | Add-Content $LogFile; continue }

  # Handle expired/nopass cases as requested
  if ($conn.Mode -eq 'expired') {
    Write-Host "$ip → SKIP: password expired (manual change required)" -ForegroundColor Yellow
    "${ip},,,,,'skip','password expired'" | Add-Content $LogFile
    continue
  }
  $session = $conn.Session
  if ($conn.Mode -eq 'nopass') {
    $pw = Exec-Step -session $session -ip $ip -cmd "/user set [find name=$Username] password=\"$Password\"" -desc 'Setting password (was blank)'
    if (-not $pw.ok) { "${ip},,,,,'skip','failed to set password'" | Add-Content $LogFile; continue }
  }

  try {
    # Ensure password is what we expect and disable expiry (v6/v7). If 'password-expire' isn't supported, fall back silently.
    try {
      Invoke-SSHCommand -SSHSession $session -Command "/user set [find name=$Username] password=\"$Password\" password-expire=0" | Out-Null
    } catch {
      Write-Host "$ip → skipping password-expire setting (not supported)" -ForegroundColor DarkYellow
    }

    $id  = ((Invoke-SSHCommand -SSHSession $session -Command $CmdGetID).Output -join "").Trim()
    if (-not $id) { $id = "unknown" }
    $ver = ((Invoke-SSHCommand -SSHSession $session -Command $CmdGetVer).Output -join "").Trim()

    if ($id -eq "MikroTik") {
      try {
        $newID = "AP-$i"
        Invoke-SSHCommand -SSHSession $session -Command "/system identity set name=$newID" | Out-Null
        $id = $newID
      } catch {
        Write-Host "$ip → failed to set identity" -ForegroundColor Yellow
      }
    }

    # skip if no wireless chip
    $wlCount = [int](((Invoke-SSHCommand -SSHSession $session -Command $CmdHasWlan).Output -join "").Trim())
    # Feedback: CAP mode + wireless count + current SSIDs
    $capState = ((Invoke-SSHCommand -SSHSession $session -Command $CmdCapOn).Output -join '').Trim()
    $capMsg = if ($capState -eq 'true') { 'ON' } else { 'OFF' }
    Write-Host ("$ip → Found CAP mode {0}" -f $capMsg) -ForegroundColor DarkCyan
    Write-Host ("$ip → Found {0} wireless network(s)" -f $wlCount) -ForegroundColor DarkCyan

    $curS1 = ((Invoke-SSHCommand -SSHSession $session -Command $CmdSSID1).Output -join '').Trim()
    $curS2 = ((Invoke-SSHCommand -SSHSession $session -Command $CmdSSID2).Output -join '').Trim()
    Write-Host ("$ip → Current WLANs: wlan1='{0}', wlan2='{1}'" -f $curS1,$curS2) -ForegroundColor DarkGray

    if ($wlCount -eq 0) { "${ip},$id,$ver,,,'skip','no wireless'" | Add-Content $LogFile; try{Remove-SSHSession -SSHSession $session|Out-Null}catch{}; continue }

    # force configuration first
    $res = Force-Config $session $ip
    Write-Host "$ip → Force-config result: SSID1='$($res.ssid1)' SSID2='$($res.ssid2)' Status='$($res.status)'" -ForegroundColor Cyan
    if ($res.ContainsKey('session') -and $null -ne $res.session) { $session = $res.session }

    if ($res.status -ne 'ready') {
      Write-Host "$ip → STOP: WLAN not internet-ready; skipping update & reboot (status=$($res.status))" -ForegroundColor Yellow
      "${ip},$id,$ver,$($res.ssid1),$($res.ssid2),'configured',$($res.status)" | Add-Content $LogFile
      goto WriteSummary
    }

    # WLAN internet OK → proceed with update (optional) then one reboot at end
    if ($DoUpdate) {
      $session = Update-MT $session $UpdateChannel $ip
      if ($null -eq $session) { "${ip},$id,$ver,,,'update','reconnect failed after update'" | Add-Content $LogFile; goto WriteSummary }
      $ver = ((Invoke-SSHCommand -SSHSession $session -Command $CmdGetVer).Output -join "").Trim()
    }

    Write-Host "$ip → Rebooting (final, all checks passed)..." -ForegroundColor Gray
    Invoke-SSHCommand -SSHSession $session -Command $CmdReboot | Out-Null
    try { Remove-SSHSession -SSHSession $session | Out-Null } catch {}
    Write-Host "$ip → Waiting after final reboot..." -ForegroundColor Gray
    if (-not (Wait-ForHost $ip 300)) { "${ip},$id,$ver,,,'reboot','timeout'" | Add-Content $LogFile; goto WriteSummary }
    $session = Reconnect-SSH $ip $Username $Password
    if ($null -eq $session) { "${ip},$id,$ver,,,'reboot','reconnect failed'" | Add-Content $LogFile; goto WriteSummary }

:WriteSummary
    # gather MAC (ether1 or first enabled ethernet)
    $mac = ""
    try {
      $macRaw = (Invoke-SSHCommand -SSHSession $session -Command ':local i [/interface ethernet find where name="ether1"]; :if ([:len $i]>0) do={:put [/interface ethernet get $i mac-address]} else={:local e [/interface ethernet find where disabled=no]; :if ([:len $e]>0) do={:put ( [/interface ethernet get $e mac-address]->0 )} else={:put ""}}').Output -join ""
      $mac = ([regex]::Match($macRaw,'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}')).Value
    } catch { $mac = "" }

    # write summary (only connected devices)
    $ssid1 = $res.ssid1; $ssid2 = $res.ssid2
    "$ip,$id,$mac,$ver,$ssid1,$ssid2" | Add-Content $SummaryFile
  } catch {
    "${ip},,,,'error',$($_.Exception.Message -replace ',',';')" | Add-Content $LogFile
  } finally {
    if ($res.status -eq 'ok') {
      try { Remove-SSHSession -SSHSession $session | Out-Null } catch {}
    }
  }
}

Write-Host "Summary: $SummaryFile" -ForegroundColor Green
Write-Host "Log:     $LogFile" -ForegroundColor Green