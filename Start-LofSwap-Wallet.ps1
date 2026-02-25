Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RootDir = Split-Path -Parent $PSCommandPath
$FrontendDir = Join-Path $RootDir 'wallet-gui\frontend'
$AppBinary = Join-Path $RootDir 'target\release\wallet-gui.exe'
$AppDistSource = Join-Path $FrontendDir 'dist'

function Require-Command {
    param([Parameter(Mandatory = $true)][string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "$Name is required. Install it first."
    }
}

Require-Command npm
Require-Command cargo

Write-Host "Building frontend..."
Push-Location $FrontendDir
try {
    npm install --no-fund --no-audit
    npm run build
}
finally {
    Pop-Location
}

Write-Host "Building wallet-gui..."
Push-Location $RootDir
try {
    cargo build --release -p wallet-gui
}
finally {
    Pop-Location
}

if (-not (Test-Path $AppBinary)) {
    throw "wallet-gui binary not found at: $AppBinary"
}

if ($env:GUI_APP_DATA_DIR -and $env:GUI_APP_DATA_DIR.Trim()) {
    $AppRuntimeDataDir = $env:GUI_APP_DATA_DIR.Trim()
}
elseif ($env:APPDATA -and $env:APPDATA.Trim()) {
    $AppRuntimeDataDir = Join-Path $env:APPDATA 'LofSwap Wallet'
}
else {
    $AppRuntimeDataDir = Join-Path $RootDir 'wallet-gui-data'
}
$AppRuntimeDistDir = Join-Path $AppRuntimeDataDir 'frontend-dist'

Write-Host "Preparing runtime assets..."
if (Test-Path $AppRuntimeDistDir) {
    Remove-Item $AppRuntimeDistDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $AppRuntimeDistDir | Out-Null
Copy-Item -Path (Join-Path $AppDistSource '*') -Destination $AppRuntimeDistDir -Recurse -Force

if ($env:NO_LAUNCH -eq '1') {
    Write-Host "Build ready: $AppBinary"
    Write-Host "Runtime data dir: $AppRuntimeDataDir"
    Write-Host "Runtime frontend dir: $AppRuntimeDistDir"
    exit 0
}

Write-Host "Launching wallet-gui..."
Remove-Item Env:GUI_APP_DEV_URL -ErrorAction SilentlyContinue
$env:GUI_APP_DATA_DIR = $AppRuntimeDataDir
$env:GUI_APP_DIST_DIR = $AppRuntimeDistDir
& $AppBinary
