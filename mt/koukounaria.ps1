# koukounaria.ps1
Import-Module Posh-SSH -ErrorAction Stop

# ---------- CONFIG ----------
$BaseNet   = "192.168.208."
$StartIP   = 2
$EndIP     = 253
$Username  = "admin"
$Password  = "is3rupgr.1821##"
$FetchUrl  = "https://upg.gr/mt/koukounaria.rsc"
$DstFile   = "koukounaria.rsc"
$SSID      = "Koukounaria Guest 9"
$LogFile   = ".\deploy-log.csv"
# ----------------------------

# RouterOS snippets
$CheckSSID = ":if ([:len [/interface wireless find where ssid=`"$SSID`"]] > 0) do={:put PRESENT} else={:put ABSENT}"
$Provision = @"
/tool fetch url=$FetchUrl dst=$DstFile check-certificate=no;
/import file-name=$DstFile;
/system reboot without-prompt=yes;
"@

# Helpers
function Ping-Fast($ip) {
  & ping.exe -n 1 -w 600 $ip 1>$null 2>$null
  return ($LASTEXITCODE -eq 0)
}
function Port22-Open($ip) {
  try { return (Test-NetConnection -ComputerName $ip -Port 22 -InformationLevel Quiet) } catch { return $false }
}
function Try-SSH($ip, $user, $pass) {
  # try NO password first
  try {
    $credNone = New-Object System.Management.Automation.PSCredential ($user,(ConvertTo-SecureString "" -AsPlainText -Force))
    $s = New-SSHSession -ComputerName $ip -Credential $credNone -AcceptKey -ErrorAction Stop
    return @{ Session=$s; Mode="nopass" }
  } catch {}
  # then WITH password
  try {
    $credPwd = New-Object System.Management.Automation.PSCredential ($user,(ConvertTo-SecureString $pass -AsPlainText -Force))
    $s = New-SSHSession -ComputerName $ip -Credential $credPwd -AcceptKey -ErrorAction Stop
    return @{ Session=$s; Mode="password" }
  } catch { return $null }
}

"IP,Reachable,P22Open,AuthMode,Action,Note" | Out-File -Encoding ascii $LogFile

for ($i=$StartIP; $i -le $EndIP; $i++) {
  $ip = "$BaseNet$i"
  Write-Host "[$ip] Ping check..." -ForegroundColor Cyan
  if (-not (Ping-Fast $ip)) { "$ip,false,false,,-,no ping"    | Add-Content $LogFile; continue }
  if (-not (Port22-Open $ip)) { "$ip,true,false,,-,ssh closed" | Add-Content $LogFile; continue }

  $conn = Try-SSH $ip $Username $Password
  if (-not $conn) { "$ip,true,true,,-,ssh auth failed" | Add-Content $LogFile; continue }

  $session = $conn.Session
  try {
    Write-Host "[$ip] Connected via $($conn.Mode). Checking SSID..."
    $out = (Invoke-SSHCommand -SSHSession $session -Command $CheckSSID -TimeOut 4000).Output -join "`n"
    if ($out -match 'PRESENT') {
      "$ip,true,true,$($conn.Mode),skipped,ssid present" | Add-Content $LogFile
      continue
    }
    Write-Host "[$ip] Provisioning..." -ForegroundColor Green
    Invoke-SSHCommand -SSHSession $session -Command $Provision | Out-Null
    "$ip,true,true,$($conn.Mode),provisioned,rebooting" | Add-Content $LogFile
  } catch {
    "$ip,true,true,$($conn.Mode),error,$($_.Exception.Message -replace ',',';')" | Add-Content $LogFile
  } finally {
    if ($session) { Remove-SSHSession -SSHSession $session | Out-Null }
  }
}

Write-Host "Done. Log saved to $LogFile" -ForegroundColor Green