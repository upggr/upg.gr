# Requires -Modules Posh-SSH

$BaseNet   = "192.168.208."
$StartIP   = 2
$EndIP     = 253
$Username  = "admin"
$Password  = "is3rupgr.1821##"
$FetchUrl  = "https://upg.gr/mt/koukounaria.rsc"
$DstFile   = "koukounaria.rsc"
$SSID      = "Koukounaria Guest 9"

# RouterOS snippets
$CheckCmd = ":if ([:len [/interface wireless find where ssid=`"$SSID`"]] > 0) do={:put PRESENT} else={:put ABSENT}"
$ProvisionCmd = @"
/tool fetch url=$FetchUrl dst=$DstFile check-certificate=no;
/import file-name=$DstFile;
/system reboot without-prompt=yes;
"@

function Try-SSH {
    param(
        [string]$IP,
        [string]$User,
        [string]$Pass
    )
    # Try no password first
    try {
        $credNone = New-Object System.Management.Automation.PSCredential ($User,(ConvertTo-SecureString "" -AsPlainText -Force))
        $s = New-SSHSession -ComputerName $IP -Credential $credNone -AcceptKey -ErrorAction Stop
        return @{ Session=$s; Mode="nopass" }
    } catch { }

    # Then try with password
    try {
        $credPwd = New-Object System.Management.Automation.PSCredential ($User,(ConvertTo-SecureString $Pass -AsPlainText -Force))
        $s = New-SSHSession -ComputerName $IP -Credential $credPwd -AcceptKey -ErrorAction Stop
        return @{ Session=$s; Mode="password" }
    } catch {
        return $null
    }
}

for ($i = $StartIP; $i -le $EndIP; $i++) {
    $IP = "$BaseNet$i"
    Write-Host "[$IP] Ping check..."
    if (-not (Test-Connection -Quiet -Count 1 -TimeoutSeconds 1 $IP)) {
        Write-Host "[$IP] Unreachable, skipping." -ForegroundColor DarkGray
        continue
    }

    $conn = Try-SSH -IP $IP -User $Username -Pass $Password
    if (-not $conn) {
        Write-Host "[$IP] SSH failed, skipping." -ForegroundColor Red
        continue
    }

    try {
        $session = $conn.Session
        Write-Host "[$IP] Connected via $($conn.Mode). Checking SSID..."
        $checkOut = (Invoke-SSHCommand -SSHSession $session -Command $CheckCmd -TimeOut 2000).Output | Out-String

        if ($checkOut -match "PRESENT") {
            Write-Host "[$IP] SSID '$SSID' already present. Skipping provisioning." -ForegroundColor Yellow
        } else {
            Write-Host "[$IP] SSID not present. Provisioning..."
            Invoke-SSHCommand -SSHSession $session -Command $ProvisionCmd | Out-Null
            Write-Host "[$IP] Provisioned and rebooting." -ForegroundColor Green
        }
    } catch {
        Write-Host "[$IP] Error: $($_.Exception.Message)" -ForegroundColor Red
    } finally {
        if ($session) { Remove-SSHSession -SSHSession $session | Out-Null }
    }
}