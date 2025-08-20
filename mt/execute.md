Set-ExecutionPolicy -Scope CurrentUser RemoteSigned -Force
Install-Module Posh-SSH -Scope CurrentUser -Force
Set-ExecutionPolicy -Scope Process Bypass -Force
iwr 'https://upg.gr/mt/koukounaria.ps1' | iex