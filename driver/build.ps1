# build.ps1 — Build the AIBridge KMDF kernel driver
#
# Prerequisites:
#   - Visual Studio 2022 with WDK installed
#   - Windows SDK 10.0.22621.0+ (or adjust below)
#
# Output: aibridge.sys copied to ..\out\

param(
    [string]$Configuration = "Release",
    [string]$Platform = "x64"
)

$ErrorActionPreference = "Stop"
Push-Location $PSScriptRoot

# ---------------------------------------------------------------------------
# Locate WDK / MSBuild
# ---------------------------------------------------------------------------
Write-Host "=== Roxy Kernel Bridge: Building aibridge.sys ($Configuration|$Platform) ==="

$vsPath = $null
$vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vsWhere) {
    $vsPath = & $vsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
}

if (-not $vsPath) {
    # Fallback: try common paths
    $candidates = @(
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Enterprise",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Professional",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\BuildTools"
    )
    foreach ($c in $candidates) {
        if (Test-Path "$c\MSBuild\Current\Bin\MSBuild.exe") {
            $vsPath = $c
            break
        }
    }
}

if (-not $vsPath) {
    Write-Error "Visual Studio 2022 not found. Install VS 2022 with WDK."
    exit 1
}

$msbuild = Join-Path $vsPath "MSBuild\Current\Bin\MSBuild.exe"
if (-not (Test-Path $msbuild)) {
    Write-Error "MSBuild.exe not found at $msbuild"
    exit 1
}

# ---------------------------------------------------------------------------
# Locate WDK (Windows Driver Kit)
# ---------------------------------------------------------------------------
$wdkRoot = $null
$wdkCandidates = @(
    "${env:ProgramFiles(x86)}\Windows Kits\10",
    "${env:ProgramFiles}\Windows Kits\10"
)
foreach ($c in $wdkCandidates) {
    if (Test-Path "$c\Include") {
        $wdkRoot = $c
        break
    }
}

if (-not $wdkRoot) {
    Write-Error "Windows Driver Kit (WDK) not found. Install WDK from https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk"
    exit 1
}

Write-Host "  Visual Studio : $vsPath"
Write-Host "  WDK           : $wdkRoot"

# ---------------------------------------------------------------------------
# Generate CMakeLists.txt if not present
# ---------------------------------------------------------------------------
if (-not (Test-Path "CMakeLists.txt")) {
    Write-Host "  Generating CMakeLists.txt..."
    @'
cmake_minimum_required(VERSION 3.20)
project(AIBridge LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_SYSTEM_VERSION 10.0)

# Prevent linking against user-mode CRT
set(CMAKE_C_FLAGS "/kernel /GS- /Gz /Zl /wd4995 /wd4996")

add_library(aibridge SHARED aibridge.c)

target_link_libraries(aibridge
    ntoskrnl.lib
    ntstrsafe.lib
    hal.lib
)

# Driver entry point (no CRT)
set_target_properties(aibridge PROPERTIES
    LINK_FLAGS "/DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry"
)

install(TARGETS aibridge DESTINATION .)
'@ | Out-File -Encoding ascii CMakeLists.txt
}

# ---------------------------------------------------------------------------
# Build with MSBuild using the WDK Driver targets
# ---------------------------------------------------------------------------
# Create a minimal .vcxproj for the driver
$vcxproj = @'
<?xml version="1.0" encoding="utf-8"?>
<Project DefaultTargets="Build" ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup Label="ProjectConfigurations">
    <ProjectConfiguration Include="Release|x64">
      <Configuration>Release</Configuration>
      <Platform>x64</Platform>
    </ProjectConfiguration>
  </ItemGroup>
  <PropertyGroup Label="Globals">
    <ProjectGuid>{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}</ProjectGuid>
    <RootNamespace>AIBridge</RootNamespace>
    <ConfigurationType>Driver</ConfigurationType>
    <DriverType>KMDF</DriverType>
    <PlatformToolset>WindowsKernelModeDriver10.0</PlatformToolset>
    <TargetVersion>Windows10</TargetVersion>
    <WindowsTargetPlatformVersion>10.0</WindowsTargetPlatformVersion>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.Default.props" />
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'" Label="Configuration">
    <UseDebugLibraries>false</UseDebugLibraries>
    <WholeProgramOptimization>true</WholeProgramOptimization>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.props" />
  <PropertyGroup>
    <OutDir>$(ProjectDir)$(Platform)\$(Configuration)\</OutDir>
    <IntDir>$(ProjectDir)$(Platform)\$(Configuration)\obj\</IntDir>
    <SpectreMitigation>false</SpectreMitigation>
  </PropertyGroup>
  <ItemDefinitionGroup>
    <ClCompile>
      <PreprocessorDefinitions>%(PreprocessorDefinitions)</PreprocessorDefinitions>
      <ExceptionHandling>false</ExceptionHandling>
      <BasicRuntimeChecks>Default</BasicRuntimeChecks>
      <BufferSecurityCheck>false</BufferSecurityCheck>
    </ClCompile>
    <Link>
      <AdditionalDependencies>%(AdditionalDependencies)</AdditionalDependencies>
      <SubSystem>Native</SubSystem>
      <Driver>true</Driver>
    </Link>
  </ItemDefinitionGroup>
  <ItemGroup>
    <ClCompile Include="aibridge.c" />
    <ClInclude Include="aibridge.h" />
  </ItemGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.targets" />
</Project>
'@

$vcxproj | Out-File -Encoding utf8 "aibridge.vcxproj"

# Build
Write-Host "  Building..."
$env:Platform = $Platform
$env:Configuration = $Configuration

& $msbuild aibridge.vcxproj /p:Configuration=$Configuration /p:Platform=$Platform /p:DriverTargetPlatform=Desktop /v:minimal

if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed. See above for errors."
    Pop-Location
    exit 1
}

# ---------------------------------------------------------------------------
# Copy output
# ---------------------------------------------------------------------------
$outDir = Join-Path $PSScriptRoot "..\out"
if (-not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
}

$sysPath = Join-Path $PSScriptRoot "$Platform\$Configuration\aibridge.sys"
if (Test-Path $sysPath) {
    Copy-Item -Force $sysPath $outDir
    Write-Host "  → Copied aibridge.sys to $outDir"
} else {
    # Also try x64\Release
    $altPath = Join-Path $PSScriptRoot "x64\Release\aibridge.sys"
    if (Test-Path $altPath) {
        Copy-Item -Force $altPath $outDir
        Write-Host "  → Copied aibridge.sys to $outDir"
    } else {
        Write-Warning "Could not find aibridge.sys in build output. Look in:\n  $sysPath\n  $altPath"
    }
}

Pop-Location
Write-Host "=== Build complete ==="