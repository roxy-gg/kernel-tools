# build.ps1 - Build the AIBridge KMDF kernel driver

param(
    [string]$Configuration = "Release",
    [string]$Platform = "x64"
)

$ErrorActionPreference = "Stop"
Push-Location $PSScriptRoot

try {
    Write-Host "=== Roxy Kernel Bridge: Building aibridge.sys ($Configuration|$Platform) ==="

    $vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    $vsPath = if (Test-Path $vsWhere) {
        & $vsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
    }

    if (-not $vsPath) {
        throw "Visual Studio 2022 with the x64 C++ toolchain was not found."
    }

    $msbuild = Join-Path $vsPath "MSBuild\Current\Bin\MSBuild.exe"
    $wdkToolset = Join-Path $vsPath "MSBuild\Microsoft\VC\v170\Platforms\$Platform\PlatformToolsets\WindowsKernelModeDriver10.0"
    if (-not (Test-Path $msbuild)) {
        throw "MSBuild.exe was not found at $msbuild"
    }
    if (-not (Test-Path $wdkToolset)) {
        throw "The WDK Visual Studio integration is missing. In Visual Studio Installer, add the Windows Driver Kit individual component. Expected: $wdkToolset"
    }

    Write-Host "  Visual Studio : $vsPath"
    Write-Host "  WDK toolset   : $wdkToolset"
    & $msbuild aibridge.vcxproj /m /t:Rebuild /p:Configuration=$Configuration /p:Platform=$Platform /p:SignMode=Off /v:minimal
    if ($LASTEXITCODE -ne 0) {
        throw "Driver build failed."
    }

    $sysPath = Join-Path $PSScriptRoot "$Platform\$Configuration\aibridge.sys"
    if (-not (Test-Path $sysPath)) {
        throw "MSBuild completed without producing aibridge.sys at $sysPath"
    }

    $outDir = Join-Path $PSScriptRoot "..\out"
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    Copy-Item -Force $sysPath $outDir
    Write-Host "  Copied aibridge.sys to $outDir"
} finally {
    Pop-Location
}
