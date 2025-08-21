  $conn = Connect-MT $ip $Username $Password
  if ($null -eq $conn) { "${ip},,,,,'skip','ssh auth failed'" | Add-Content $LogFile; continue }
  $session = $conn.Session

  try {
    # set password if we logged in with none
    if ($conn.Mode -eq 'nopass') { Invoke-SSHCommand -SSHSession $session -Command "/user set [find name=$Username] password=\"$Password\"" | Out-Null }

    # Ensure password is what we expect and disable expiry (v6/v7). If 'password-expire' isn't supported, fall back silently.
    try {
      Invoke-SSHCommand -SSHSession $session -Command "/user set [find name=$Username] password=\"$Password\" password-expire=0" | Out-Null
    } catch {
      try { Invoke-SSHCommand -SSHSession $session -Command "/user set [find name=$Username] password=\"$Password\"" | Out-Null } catch {}
    }

    $id  = ((Invoke-SSHCommand -SSHSession $session -Command $CmdGetID).Output -join "").Trim()