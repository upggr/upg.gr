Set-ExecutionPolicy -Scope CurrentUser RemoteSigned -Force
Install-Module Posh-SSH -Scope CurrentUser -Force
Set-ExecutionPolicy -Scope Process Bypass -Force
iwr 'https://upg.gr/mt/koukounaria.ps1' | iex



iwr 'https://raw.githubusercontent.com/upggr/upg.gr/refs/heads/master/mt/koukounaria.ps1' | iex