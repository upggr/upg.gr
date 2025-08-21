# koukounaria.ps1 — scan & FORCE-config MikroTik APs (no .rsc)
Import-Module Posh-SSH -ErrorAction Stop

# ======== USER CONFIG ========
$BaseNet        = "192.168.208."
$StartIP        = 116        # inclusive
$EndIP          = 118       # inclusive
$Username       = "admin"
$Password       = "is3rupgr.1821##"   # will be set if device has no password
$SSID           = "Koukounaria Guest 9"
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
  # try no password first
  try {
    $credNone = New-Cred $user ""
    $s = New-SSHSession -ComputerName $ip -Credential $credNone -AcceptKey -ConnectionTimeout 15000 -ErrorAction Stop
    return @{ Session=$s; Mode='nopass' }
  } catch {}
  # then the provided password
  try {
    $credPwd = New-Cred $user $pass
    $s = New-SSHSession -ComputerName $ip -Credential $credPwd -AcceptKey -ConnectionTimeout 15000 -ErrorAction Stop
    return @{ Session=$s; Mode='password' }
  } catch {
    $msg = $_.Exception.Message
    Write-Host ("Auth failed for {0}: {1}" -f $ip, $msg) -ForegroundColor Red
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

# ---- RouterOS one-liners ----
$CmdGetID    = ':put [/system identity get name]'
$CmdGetVer   = ':put [/system resource get version]'
$CmdHasWlan  = ':put ([:len [/interface find where type~"wlan"]])'
$CmdSSID1    = ':put [/interface wireless get wlan1 ssid]'
$CmdSSID2    = ':put [/interface wireless get wlan2 ssid]'
$CmdDis1     = ':put [/interface wireless get wlan1 disabled]'
$CmdDis2     = ':put [/interface wireless get wlan2 disabled]'

# ---- FORCE-config blocks (always apply) ----
$CmdDecap = @"
/interface wireless cap set enabled=no interfaces="" discovery-interfaces="" caps-man-addresses="" certificate="" static-virtual=no
:if ([:len [/system package find where name="caps-man"]]>0) do={/system package disable caps-man}
:do { /caps-man manager set enabled=no } on-error={}
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

$CmdForceWireless = @"
# hard reset wireless and remove extras
/interface wireless disable [find]
/interface wireless remove [find where master-interface!=""]
/interface wireless
:if ([:len [find where name="wlan1"]]>0) do={reset-configuration wlan1}
:if ([:len [find where name="wlan2"]]>0) do={reset-configuration wlan2}
/interface wireless set [find] scan-list=default country=no_country_set channel-width=20mhz
/interface wireless access-list remove [find]
/interface wireless connect-list remove [find]
/interface wireless security-profiles remove [find where name!="default"]
/interface wireless security-profiles add name=guest_open authentication-types="" unicast-ciphers="" group-ciphers=""
:if ([:len [find where name="wlan1"]]>0) do={set wlan1 mode=ap-bridge ssid="$SSID" security-profile=guest_open vlan-mode=use-tag vlan-id=$VlanId disabled=no}
:if ([:len [find where name="wlan2"]]>0) do={set wlan2 mode=ap-bridge ssid="$SSID" security-profile=guest_open vlan-mode=use-tag vlan-id=$VlanId disabled=no}
/interface wireless enable [find where name="wlan1"]
/interface wireless enable [find where name="wlan2"]
"@

# Bridge all ports; trunk VLAN $VlanId; put management on VLAN $VlanId (DHCP client on bridge VLAN interface)
$CmdNet = @"
# Ensure bridge exists
:local brId [/interface bridge find]; :local brName ""; :if ([:len $brId]>0) do={:set brName [/interface bridge get ($brId->0) name]} else={/interface bridge add name=bridge1; :set brName "bridge1"}

# Add ALL ethernet ports to the bridge
/interface bridge port
:foreach e in=[/interface ethernet find] do={ :local n [/interface ethernet get $e name]; :if ([:len [find where bridge=$brName interface=$n]]=0) do={ add bridge=$brName interface=$n } }

# Add WLANs to the bridge if present
:if ([:len [/interface wireless find where name="wlan1"]]>0 && [:len [find where bridge=$brName interface="wlan1"]]=0) do={ add bridge=$brName interface=wlan1 }
:if ([:len [/interface wireless find where name="wlan2"]]>0 && [:len [find where bridge=$brName interface="wlan2"]]=0) do={ add bridge=$brName interface=wlan2 }

# VLAN $VlanId tagged on bridge + all Ethernet + present WLANs
:local tagged "$brName"
:foreach e in=[/interface ethernet find] do={ :set tagged "$tagged,[:tostr [/interface ethernet get $e name]]" }
:if ([:len [/interface wireless find where name="wlan1"]]>0) do={ :set tagged "$tagged,wlan1" }
:if ([:len [/interface wireless find where name="wlan2"]]>0) do={ :set tagged "$tagged,wlan2" }

/interface bridge vlan
:if ([:len [find where bridge=$brName vlan-ids=$VlanId]]=0) do={ add bridge=$brName vlan-ids=$VlanId tagged=$tagged } else={ set [find where bridge=$brName vlan-ids=$VlanId] tagged=$tagged }

/interface bridge set [find where name=$brName] vlan-filtering=yes

# Management on VLAN: create VLAN interface on bridge and move DHCP client there
/interface vlan
:if ([:len [find where name="mgmt.$VlanId"]]=0) do={ add name="mgmt.$VlanId" interface=$brName vlan-id=$VlanId } else={ set [find where name="mgmt.$VlanId"] interface=$brName vlan-id=$VlanId }

/ip dhcp-client
:foreach i in=[find] do={ remove $i }
:add interface="mgmt.$VlanId" disabled=no
"@

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
  # remove CAP/caps-man, wipe wifi, bridge/trunk VLAN, reboot, verify loop
  Invoke-SSHCommand -SSHSession $session -Command $CmdDecap       | Out-Null
  Invoke-SSHCommand -SSHSession $session -Command $CmdNukeCapsMan  | Out-Null
  Invoke-SSHCommand -SSHSession $session -Command $CmdForceWireless| Out-Null
  Invoke-SSHCommand -SSHSession $session -Command $CmdNet          | Out-Null
  Invoke-SSHCommand -SSHSession $session -Command $CmdReboot       | Out-Null
  try { Remove-SSHSession -SSHSession $session | Out-Null } catch {}
  if (-not (Wait-ForHost $ip 300)) { return @{ssid1=''; ssid2=''; status='reboot-timeout'} }
  $s = Reconnect-SSH $ip $Username $Password
  if ($null -eq $s) { return @{ssid1=''; ssid2=''; status='reconnect-failed'} }
  # verify and enforce up to 60s
  $deadline = [DateTime]::UtcNow.AddSeconds(60)
  do {
    $s1 = ((Invoke-SSHCommand -SSHSession $s -Command $CmdSSID1 -TimeOut 3000).Output -join "").Trim()
    $s2 = ((Invoke-SSHCommand -SSHSession $s -Command $CmdSSID2 -TimeOut 3000).Output -join "").Trim()
    $d1 = ((Invoke-SSHCommand -SSHSession $s -Command $CmdDis1  -TimeOut 3000).Output -join "").Trim()
    $d2 = ((Invoke-SSHCommand -SSHSession $s -Command $CmdDis2  -TimeOut 3000).Output -join "").Trim()
    $ok1 = (($s1 -eq $SSID -and $d1 -eq 'false') -or ($s1 -eq '' -and $d1 -eq 'true'))
    $ok2 = (($s2 -eq $SSID -and $d2 -eq 'false') -or ($s2 -eq '' -and $d2 -eq 'true'))
    if ($ok1 -and $ok2) { break }
    $enforce = @"
/interface wireless set [find where name="wlan1"] mode=ap-bridge ssid="$SSID" security-profile=guest_open vlan-mode=use-tag vlan-id=$VlanId disabled=no
/interface wireless set [find where name="wlan2"] mode=ap-bridge ssid="$SSID" security-profile=guest_open vlan-mode=use-tag vlan-id=$VlanId disabled=no
/interface wireless enable [find where name="wlan1"]
/interface wireless enable [find where name="wlan2"]
"@
    Invoke-SSHCommand -SSHSession $s -Command $enforce | Out-Null
    Start-Sleep -Seconds 3
  } while ([DateTime]::UtcNow -lt $deadline)
  $final1 = ((Invoke-SSHCommand -SSHSession $s -Command $CmdSSID1).Output -join "").Trim()
  $final2 = ((Invoke-SSHCommand -SSHSession $s -Command $CmdSSID2).Output -join "").Trim()
  return @{ssid1=$final1; ssid2=$final2; status='ok'; session=$s}
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
  $session = $conn.Session

  try {
    # set password if we logged in with none
    if ($conn.Mode -eq 'nopass') {
      try {
        Invoke-SSHCommand -SSHSession $session -Command "/user set [find name=$Username] password=\"$Password\"" | Out-Null
      } catch {
        Write-Host "$ip → skipping password set (likely password expired screen)" -ForegroundColor Yellow
      }
    }

    # Ensure password is what we expect and disable expiry (v6/v7). If 'password-expire' isn't supported, fall back silently.
    try {
      Invoke-SSHCommand -SSHSession $session -Command "/user set [find name=$Username] password=\"$Password\" password-expire=0" | Out-Null
    } catch {
      Write-Host "$ip → skipping password-expire setting (not supported)" -ForegroundColor DarkYellow
    }

    $id  = ((Invoke-SSHCommand -SSHSession $session -Command $CmdGetID).Output -join "").Trim()
    $ver = ((Invoke-SSHCommand -SSHSession $session -Command $CmdGetVer).Output -join "").Trim()

    # skip if no wireless chip
    $wlCount = [int](((Invoke-SSHCommand -SSHSession $session -Command $CmdHasWlan).Output -join "").Trim())
    if ($wlCount -eq 0) { "${ip},$id,$ver,,,'skip','no wireless'" | Add-Content $LogFile; try{Remove-SSHSession -SSHSession $session|Out-Null}catch{}; continue }

    # update (optional)
    if ($DoUpdate) {
      $session = Update-MT $session $UpdateChannel $ip
      if ($null -eq $session) { "${ip},$id,$ver,,,'update','reconnect failed after update'" | Add-Content $LogFile; continue }
      $ver = ((Invoke-SSHCommand -SSHSession $session -Command $CmdGetVer).Output -join "").Trim()
    }

    # force configuration
    $res = Force-Config $session $ip
    if ($res.ContainsKey('session') -and $null -ne $res.session) { $session = $res.session }
    if ($null -eq $session) { $session = Reconnect-SSH $ip $Username $Password }
    $ssid1 = $res.ssid1; $ssid2 = $res.ssid2
    "${ip},$id,$ver,$ssid1,$ssid2,'configured',$($res.status)" | Add-Content $LogFile

    # gather MAC (ether1 or first enabled ethernet)
    $mac = ""
    try {
      $macRaw = (Invoke-SSHCommand -SSHSession $session -Command ':local i [/interface ethernet find where name="ether1"]; :if ([:len $i]>0) do={:put [/interface ethernet get $i mac-address]} else={:local e [/interface ethernet find where disabled=no]; :if ([:len $e]>0) do={:put ( [/interface ethernet get $e mac-address]->0 )} else={:put ""}}').Output -join ""
      $mac = ([regex]::Match($macRaw,'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}')).Value
    } catch { $mac = "" }

    # write summary (only connected devices)
    "$ip,$id,$mac,$ver,$ssid1,$ssid2" | Add-Content $SummaryFile
  } catch {
    "${ip},,,,'error',$($_.Exception.Message -replace ',',';')" | Add-Content $LogFile
  } finally { try { Remove-SSHSession -SSHSession $session | Out-Null } catch {} }
}

Write-Host "Summary: $SummaryFile" -ForegroundColor Green
Write-Host "Log:     $LogFile" -ForegroundColor Green