# Installe l'agent OmniUp VPN sous Windows : télécharge le binaire de la
# dernière release et wintun.dll, puis enregistre le service Windows
# (démarrage automatique).
#
# Dans un PowerShell **administrateur** :
#   iwr -useb https://raw.githubusercontent.com/jeanbaptisteboitel-boop/omniup-vpn/main/scripts/install-omnid.ps1 -OutFile "$env:TEMP\install-omnid.ps1"
#   & "$env:TEMP\install-omnid.ps1" -Server https://vpn.omniup.fr -AuthKey omkey-...

param(
    [Parameter(Mandatory = $true)][string]$Server,
    [Parameter(Mandatory = $true)][string]$AuthKey
)

$ErrorActionPreference = "Stop"
$Repo = "jeanbaptisteboitel-boop/omniup-vpn"
$WintunVersion = "0.14.1"
$InstallDir = "$env:ProgramFiles\OmniUp"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Lancez ce script dans un PowerShell administrateur."
}
if ([Environment]::Is64BitOperatingSystem -eq $false -or $env:PROCESSOR_ARCHITECTURE -ne "AMD64") {
    Write-Error "Seule l'architecture amd64 est fournie pour l'instant."
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

Write-Host "» téléchargement de la dernière release (windows-amd64)…"
Invoke-WebRequest -UseBasicParsing `
    -Uri "https://github.com/$Repo/releases/latest/download/omnid-windows-amd64.exe" `
    -OutFile "$InstallDir\omnid.exe"

if (-not (Test-Path "$InstallDir\wintun.dll")) {
    Write-Host "» téléchargement de wintun $WintunVersion…"
    $zip = "$env:TEMP\wintun.zip"
    Invoke-WebRequest -UseBasicParsing `
        -Uri "https://www.wintun.net/builds/wintun-$WintunVersion.zip" -OutFile $zip
    $tmp = "$env:TEMP\wintun-extract"
    Expand-Archive -Path $zip -DestinationPath $tmp -Force
    Copy-Item "$tmp\wintun\bin\amd64\wintun.dll" "$InstallDir\wintun.dll"
    Remove-Item -Recurse -Force $tmp, $zip
}

Write-Host "» installation du service (enrôlement au premier démarrage)…"
& "$InstallDir\omnid.exe" service uninstall 2>$null | Out-Null
& "$InstallDir\omnid.exe" service install --server $Server --auth-key $AuthKey
if ($LASTEXITCODE -ne 0) { Write-Error "l'installation du service a échoué" }

Write-Host "» terminé. Vérifiez avec :  & `"$InstallDir\omnid.exe`" status"
Write-Host "  (journal : $env:ProgramData\OmniUp\omnid.log)"
