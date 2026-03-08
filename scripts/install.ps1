# Revelion Daemon Installer for Windows
# Usage (in PowerShell): irm https://raw.githubusercontent.com/RevelionAI/revelion-daemon/main/scripts/install.ps1 | iex
# With token: $env:REVELION_TOKEN='your-token'; irm https://raw.githubusercontent.com/RevelionAI/revelion-daemon/main/scripts/install.ps1 | iex

$ErrorActionPreference = 'Stop'

$Token = $env:REVELION_TOKEN
$Repo = "RevelionAI/revelion-daemon"
$InstallDir = "$env:LOCALAPPDATA\Revelion"
$BinaryName = "revelion.exe"
$ConfigDir = "$env:USERPROFILE\.revelion"

function Write-Info($msg) { Write-Host "[revelion] " -ForegroundColor Cyan -NoNewline; Write-Host $msg }
function Write-Ok($msg) { Write-Host "[revelion] " -ForegroundColor Green -NoNewline; Write-Host $msg }
function Write-Err($msg) { Write-Host "[revelion] " -ForegroundColor Red -NoNewline; Write-Host $msg }

# Banner
Write-Host ""
Write-Host "  ____                 _ _             " -ForegroundColor Cyan
Write-Host " |  _ \ _____   _____| (_) ___  _ __  " -ForegroundColor Cyan
Write-Host " | |_) / _ \ \ / / _ \ | |/ _ \| '_ \ " -ForegroundColor Cyan
Write-Host " |  _ <  __/\ V /  __/ | | (_) | | | |" -ForegroundColor Cyan
Write-Host " |_| \_\___| \_/ \___|_|_|\___/|_| |_|" -ForegroundColor Cyan
Write-Host ""
Write-Info "Daemon Installer for Windows"
Write-Host ""

# Get latest daemon release
Write-Info "Fetching latest version..."
$releases = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases" -UseBasicParsing
$daemonRelease = $releases | Where-Object { $_.tag_name -like "daemon-v*" } | Select-Object -First 1

if (-not $daemonRelease) {
    Write-Err "No daemon releases found."
    exit 1
}

$version = $daemonRelease.tag_name
$asset = $daemonRelease.assets | Where-Object { $_.name -eq "revelion-windows-amd64.exe" }

if (-not $asset) {
    Write-Err "No Windows binary found in release $version"
    exit 1
}

# Create install directory
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# Download
$downloadUrl = $asset.browser_download_url
$destPath = Join-Path $InstallDir $BinaryName

Write-Info "Downloading $version..."
Write-Host "  $downloadUrl" -ForegroundColor DarkGray
Invoke-WebRequest -Uri $downloadUrl -OutFile $destPath -UseBasicParsing

Write-Ok "Downloaded to $destPath"

# Add to PATH if not already there
$currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($currentPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("PATH", "$currentPath;$InstallDir", "User")
    $env:PATH = "$env:PATH;$InstallDir"
    Write-Ok "Added $InstallDir to PATH"
}

# Configure with token
if ($Token) {
    if (-not (Test-Path $ConfigDir)) {
        New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
    }

    $config = @{
        api_token = $Token
        brain_url = "wss://revelion-brain.fly.dev"
        sandbox_image = "ghcr.io/revelionai/revelion-sandbox:0.1.0"
    } | ConvertTo-Json

    $configPath = Join-Path $ConfigDir "config.json"
    Set-Content -Path $configPath -Value $config -Encoding UTF8
    Write-Ok "Configured with API token"
}

# Check Docker
$dockerAvailable = $false
try {
    docker info 2>$null | Out-Null
    $dockerAvailable = $true
} catch {
    Write-Host ""
    Write-Err "Docker Desktop is not running."
    Write-Info "Install Docker Desktop: https://docs.docker.com/desktop/install/windows-install/"
}

Write-Host ""
if ($Token -and $dockerAvailable) {
    Write-Ok "Starting daemon..."
    Write-Host ""
    & $destPath start
} elseif ($Token) {
    Write-Ok "Installation complete!"
    Write-Host ""
    Write-Info "Start Docker Desktop, then run:"
    Write-Host "  revelion start" -ForegroundColor DarkGray
} else {
    Write-Ok "Installation complete!"
    Write-Host ""
    Write-Info "Authenticate with your API token (find it at app.revelion.ai/agents):"
    Write-Host "  revelion auth YOUR_API_TOKEN" -ForegroundColor DarkGray
    Write-Host ""
    Write-Info "Then start the daemon:"
    Write-Host "  revelion start" -ForegroundColor DarkGray
}
