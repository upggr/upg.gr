# koukounaria.ps1
Import-Module Posh-SSH -ErrorAction Stop

# -------- CONFIG --------
$BaseNet   = "192.168.208."
$StartIP   = 2             # set 101/101 to test one device first
$EndIP     = 253
$Username  = "admin"
$Password  = "is3rupgr.1821##"
$FetchUrl  = "https://upg.gr/mt/koukounaria.rsc"
$DstFile   = "koukounaria.rsc"
$SSID      = "Koukounaria Guest 9"
$LogFile   = ".\deploy-log.csv"
# ------------------------

# RouterOS command snippets
$CmdGetID     = ':put [/system identity get name]'
# first non-disabled ethernet MAC
$CmdGetMAC    = ':local m ""; :foreach i in=[/interface ethernet find where disabled=no] do={:set m [/interface ethernet get $i mac-address]; :break}; :put $m'
$CmdChkSSID   = ":if ([:len [/interface wireless find where ssid=`"$SSID`"]] > 0) do={:put PRESENT} else={:put ABSENT}"
$CmdProvision = @"
/tool fetch url=$FetchUrl dst=$DstFile check-certificate=no;
/import file-name=$DstFile;
"@
$CmdSetLT     = '/system package update set channel=long-term'
$CmdCheckUpd  = '/system package update check-for-updates'
$CmdGetInst   = ':put [/system package update get installed-version]'
$CmdGetLatest = ':put [/system package update get latest-version]'

function Ping-Fast($ip) { & ping.exe -n 1 -w 600 $ip 1>$null 2>$null; return ($LASTEXITCODE -eq 0) }
function Port22-Open($ip) { try { Test-NetConnection -ComputerName $ip -Port 22 -InformationLevel Quiet } catch { $false } }

function Try-SSH($ip, $user, $pass) {
  try {  # no password
    $credNone = New-Object PSCredential ($user,(ConvertTo-SecureString "" -AsPlainText -Force))
    $s = New-SSHSession -ComputerName $ip -Credential $credNone -AcceptKey -ErrorAction Stop
    return @{ Session=$s; Mode="nopass" }
  } catch {}
  try {  # with password
    $credPwd = New-Object PSCredential ($user,(ConvertTo-SecureString $pass -AsPlainText -Force))
    $s = New-SSHSession -ComputerName $ip -Credential $credPwd -AcceptKey -ErrorAction Stop
    return @{ Session=$s; Mode="password" }
  } catch { return $null }
}

"IP,Identity,MAC,Reachable,P22Open,AuthMode,SSIDAction,UpdateAction,Note" | Out-File -Encoding ascii $LogFile

for ($i=$StartIP; $i -le $EndIP; $i++) {
  $ip = "$BaseNet$i"
  Write-Host "[$ip] Ping check..." -ForegroundColor Cyan
  if (-not (Ping-Fast $ip)) { "$ip,,,false,false,,,no ping" | Add-Content $LogFile; continue }
  if (-not (Port22-Open $ip)) { "$ip,,,true,false,,,ssh closed" | Add-Content $LogFile; continue }

  $conn = Try-SSH $ip $Username $Password
  if (-not $conn) { "$ip,,,true,true,,,ssh auth failed" | Add-Content $LogFile; continue }

  $session  = $conn.Session
  $identity = ""; $mac = ""; $ssidAction = ""; $updAction = ""; $note = ""
  try {
    # Identity & MAC
    $identity = ((Invoke-SSHCommand -SSHSession $session -Command $CmdGetID  -TimeOut 4000).Output -join "`n").Trim()
    $mac      = ((Invoke-SSHCommand -SSHSession $session -Command $CmdGetMAC -TimeOut 4000).Output -join "`n").Trim()
    if ($identity) { Write-Host "[$ip] Identity: $identity  MAC: $mac" -ForegroundColor Gray }

    # SSID presence
    $chkOut = (Invoke-SSHCommand -SSHSession $session -Command $CmdChkSSID -TimeOut 4000).Output -join "`n"
    if ($chkOut -match 'PRESENT') {
      $ssidAction = "skipped"
      Write-Host "[$ip] SSID '$SSID' already present. Skipping provision." -ForegroundColor Yellow
    } else {
      $ssidAction = "provisioned"
      Write-Host "[$ip] Provisioning..." -ForegroundColor Green
      Invoke-SSHCommand -SSHSession $session -Command $CmdProvision | Out-Null
    }

    # Update to long-term if newer exists
    Invoke-SSHCommand -SSHSession $session -Command $CmdSetLT    | Out-Null
    Invoke-SSHCommand -SSHSession $session -Command $CmdCheckUpd | Out-Null
    $installed = ((Invoke-SSHCommand -SSHSession $session -Command $CmdGetInst   -TimeOut 4000).Output -join "`n").Trim()
    $latest    = ((Invoke-SSHCommand -SSHSession $session -Command $CmdGetLatest -TimeOut 4000).Output -join "`n").Trim()

    if ($latest -and $installed -and ($latest -ne $installed)) {
      Write-Host "[$ip] Updating RouterOS $installed -> $latest (long-term)..." -ForegroundColor Cyan
      # Try download-install (newer v6.43+/v7); if it errors, fall back to download+reboot
      try {
        Invoke-SSHCommand -SSHSession $session -Command '/system package update download-install' -TimeOut 120000 | Out-Null
        $updAction = "download-install (to $latest)"
      } catch {
        Invoke-SSHCommand -SSHSession $session -Command '/system package update download' -TimeOut 120000 | Out-Null
        Invoke-SSHCommand -SSHSession $session -Command '/system reboot without-prompt=yes' | Out-Null
        $updAction = "download+reboot (to $latest)"
      }
    } else {
      $updAction = "up-to-date ($installed)"
    }

    "$ip,$identity,$mac,true,true,$($conn.Mode),$ssidAction,$updAction,$note" | Add-Content $LogFile
  } catch {
    "$ip,$identity,$mac,true,true,$($conn.Mode),$ssidAction,$updAction,$($_.Exception.Message -replace ',',';')" | Add-Content $LogFile
  } finally {
    if ($session) { Remove-SSHSession -SSHSession $session | Out-Null }
  }
}

Write-Host "Done. Log saved to $LogFile" -ForegroundColor Green