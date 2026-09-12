# install.ps1 — Install and start the AIBridge kernel driver
#
# Must be run as Administrator.
#
# Prerequisites:
#   - Testsigning enabled: bcdedit /set testsigning on
#   - aibridge.sys in the out/ directory (run .\driver\build.ps1 first)
#   - The .sys must be placed in %windir%\system32\drivers\ (or full path in sc.exe)

param(
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"

# Check for admin
$isAdmin = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

$serviceName = "AIBridge"
$sysPath = Join-Path $PSScriptRoot "out\aibridge.sys"

if ($Uninstall) {
    Write-Host "=== Uninstalling AIBridge driver ==="

    $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -eq "Running") {
            Write-Host "  Stopping service..."
            sc.exe stop $serviceName 2>&1 | Out-Null
            Start-Sleep -Seconds 2
        }
        Write-Host "  Deleting service..."
        sc.exe delete $serviceName 2>&1 | Out-Null
        Write-Host "  Service removed."
    } else {
        Write-Host "  Service not found."
    }

    Write-Host "=== Uninstall complete ==="
    Write-Host ""
    Write-Host "Note: Delete $sysPath manually if desired. Reboot to fully unload."
    exit 0
}

# --- Install ---
if (-not (Test-Path $sysPath)) {
    # Try in the driver build tree
    $altPath = Join-Path $PSScriptRoot "driver\x64\Release\aibridge.sys"
    if (Test-Path $altPath) {
        $sysPath = $altPath
    } else {
        Write-Error "aibridge.sys not found. Run .\driver\build.ps1 first."
        exit 1
    }
}

Write-Host "=== Installing AIBridge kernel driver ==="
Write-Host "  Driver path: $sysPath"

# Stop and delete existing service
$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "  Removing existing service..."
    sc.exe stop $serviceName 2>&1 | Out-Null
    Start-Sleep -Seconds 2
    sc.exe delete $serviceName 2>&1 | Out-Null
    Start-Sleep -Seconds 1
}

# Create and start the service
Write-Host "  Creating kernel service..."
sc.exe create $serviceName type= kernel start= demand binPath= "$sysPath" 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to create service."
    exit 1
}

Write-Host "  Starting service..."
sc.exe start $serviceName 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Warning "Service created but failed to start. Check test signing mode."
    Write-Warning "Run: bcdedit /set testsigning on  and reboot."
} else {
    Write-Host "  Service started successfully."
}

Write-Host "=== Install complete ==="
Write-Host ""
Write-Host "Device: \\\\.\\AIAgent is now available."
Write-Host "Test:   echo '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}' | .\out\roxy-kernel-bridge.exe"