# build.ps1 — Build the Rust MCP bridge
#
# Output: roxy-kernel-bridge.exe copied to ..\out\

param(
    [string]$Configuration = "release"
)

$ErrorActionPreference = "Stop"
Push-Location $PSScriptRoot

Write-Host "=== Roxy Kernel Bridge: Building roxy-kernel-bridge.exe ==="

# Check for cargo
$cargo = Get-Command cargo -ErrorAction SilentlyContinue
if (-not $cargo) {
    Write-Error "Rust/cargo not found. Install from https://rustup.rs"
    exit 1
}

Write-Host "  Rust toolchain: $(rustup default 2>$null)"
Write-Host "  Building ($Configuration)..."

$buildArgs = @("build")
if ($Configuration -eq "release") {
    $buildArgs += "--release"
}

& cargo $buildArgs 2>&1 | ForEach-Object { Write-Host "  $_" }

if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed."
    Pop-Location
    exit 1
}

# Copy output
$outDir = Join-Path $PSScriptRoot "..\out"
if (-not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
}

$exePath = if ($Configuration -eq "release") {
    Join-Path $PSScriptRoot "target\release\roxy-kernel-bridge.exe"
} else {
    Join-Path $PSScriptRoot "target\debug\roxy-kernel-bridge.exe"
}

if (Test-Path $exePath) {
    Copy-Item -Force $exePath $outDir
    Write-Host "  → Copied roxy-kernel-bridge.exe to $outDir"
} else {
    Write-Error "Build output not found at: $exePath"
    exit 1
}

Pop-Location
Write-Host "=== Build complete ==="