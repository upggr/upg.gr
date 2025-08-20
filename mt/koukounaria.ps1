# Requires: Install-Module Posh-SSH -Force
Import-Module Posh-SSH -ErrorAction Stop

$BaseNet   = "192.168.208."
$StartIP   = 2
$EndIP     = 253
$Username  = "admin"
$Password  = "is3rupgr.1821##"
$FetchUrl  = "https://upg.gr/koukounaria.rsc"
$DstFile   = "koukounaria.rsc"
$SSID      = "Koukounaria Guest 9"
$LogFile   = ".\deploy-log.csv"

# RouterOS checks/commands (v6+)
$CheckSSID = ":if ([:len [/interface wireless find where ssid=`"$SSID`"]] > 0) do={:put PRESENT} else={:put ABSENT}"
$Provision = @"
/tool fetch url=$FetchUrl dst=$DstFile check-certificate=no;
/import file-name=$DstFile;
/system reboot without-prompt=yes;
"@

# start log
"IP,Reachable,P22Open,AuthMode,Action,Note" | Out-File -Encoding ascii $LogFile

function Ping-Fast($ip) {
  $p = & ping.exe -n 1 -w 600 $ip 2>$null
  return ($LASTEXITCODE -eq 0)
}

function Port22-Open($ip) {
  try { return (Test-NetConnection -ComputerName $ip -Port 22 -InformationLevel Quiet) } catch { return $false }
}

function Try-SSH($ip, $user, $pass) {
  # try NO password
  try {
    $credNone = New-Object System.Management.Automation.PSCredential ($user,(ConvertTo-SecureString "" -AsPlainText -Force))
    $s = New-SSHSession -ComputerName $ip -Credential $credNone -AcceptKey -ErrorAction Stop
    return @{Session=$s; Mode="nopass"}
  } catch {}

  # try WITH password
  try {
    $credPwd = New-Object System.Management.Automation.PSCredential ($user,(ConvertTo-SecureString $pass -AsPlainText -Force))
    $s = New-SSHSession -ComputerName $ip -Credential $credPwd -AcceptKey -ErrorAction Stop
    return @{Session=$s; Mode="password"}
  } catch { return $null }
}

for ($i=$StartIP; $i -le $EndIP; $i++) {
  $ip = "$BaseNet$i"
  Write-Host "[$ip] Ping check..." -ForegroundColor Cyan
  $alive = Ping-Fast $ip
  if (-not $alive) { "$ip,false,false,,-,no ping" | Add-Content $LogFile; continue }

  $p22 = Port22-Open $ip
  if (-not $p22) {
    Write-Host "[$ip] TCP/22 closed (SSH disabled?)" -ForegroundColor DarkYellow
    "$ip,true,false,,-,ssh closed" | Add-Content $LogFile
    continue
  }

  $conn = Try-SSH $ip $Username $Password
  if (-not $conn) {
    Write-Host "[$ip] SSH auth failed." -ForegroundColor Red
    "$ip,true,true,,-,ssh auth failed" | Add-Content $LogFile
    continue
  }

  $session = $conn.Session
  try {
    Write-Host "[$ip] Connected via $($conn.Mode). Checking SSID..."
    $out = (Invoke-SSHCommand -SSHSession $session -Command $CheckSSID -TimeOut 3000).Output | Out-String
    if ($out -match "PRESENT") {
      Write-Host "[$ip] SSID already present. Skipping." -ForegroundColor Yellow
      "$ip,true,true,$($conn.Mode),skipped,ssid present" | Add-Content $LogFile
    } else {
      Write-Host "[$ip] Provisioning..." -ForegroundColor Green
      Invoke-SSHCommand -SSHSession $session -Command $Provision | Out-Null
      "$ip,true,true,$($conn.Mode),provisioned,rebooting" | Add-Content $LogFile
    }
  } catch {
    "$ip,true,true,$($conn.Mode),error,$($_.Exception.Message.Replace(',', ';'))" | Add-Content $LogFile
  } finally {
    if ($session) { Remove-SSHSession -SSHSession $session | Out-Null }
  }
}

Write-Host "Done. Log saved to $LogFile" -ForegroundColor Green