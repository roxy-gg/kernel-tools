param(
    [Parameter(Mandatory)]
    [string]$DriverPath,

    [Parameter(Mandatory)]
    [string]$BridgePath,

    [string]$CertificatePath,
    [string]$ServiceName = "RoxyKernelToolsValidation",
    [ValidateRange(1, 1000)]
    [int]$LoadCycles = 20,
    [string]$OutputDirectory = (Join-Path $PSScriptRoot "..\validation-results"),
    [switch]$ConfigureKernelDumps
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$isAdmin = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    throw "Run this validation script from an elevated PowerShell session."
}

$DriverPath = (Resolve-Path -LiteralPath $DriverPath).Path
$BridgePath = (Resolve-Path -LiteralPath $BridgePath).Path
if ($CertificatePath) {
    $CertificatePath = (Resolve-Path -LiteralPath $CertificatePath).Path
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$runDirectory = Join-Path $OutputDirectory (Get-Date -Format "yyyyMMdd-HHmmss")
New-Item -ItemType Directory -Force -Path $runDirectory | Out-Null
$logPath = Join-Path $runDirectory "validation.log"
$reportPath = Join-Path $runDirectory "validation-report.json"
$gatePath = Join-Path $runDirectory "mcp-eligibility.json"

if (-not ("KernelValidationNative" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class KernelValidationNative
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DeviceIoControl(
        SafeFileHandle device,
        uint ioControlCode,
        byte[] inBuffer,
        int inBufferSize,
        byte[] outBuffer,
        int outBufferSize,
        out int bytesReturned,
        IntPtr overlapped);
}
"@
}

$ioctls = [ordered]@{
    ReadProcessMemory = [Convert]::ToUInt32("80006000", 16)
    ListProcesses = [Convert]::ToUInt32("80006004", 16)
    KillProcess = [Convert]::ToUInt32("8000A008", 16)
    ReadRegistry = [Convert]::ToUInt32("8000600C", 16)
    WriteRegistry = [Convert]::ToUInt32("8000A010", 16)
    ListFiles = [Convert]::ToUInt32("80006014", 16)
    ReadFile = [Convert]::ToUInt32("80006018", 16)
    WriteFile = [Convert]::ToUInt32("8000A01C", 16)
}

$results = [System.Collections.Generic.List[object]]::new()
$stageResults = [System.Collections.Generic.List[object]]::new()
$addedCertificates = [System.Collections.Generic.List[string]]::new()
$device = $null
$serviceCreated = $false
$driverLoaded = $false
$dumpConfigurationBefore = $null
$dumpFilesBefore = @()
$runStartedAt = Get-Date
$transcriptStarted = $false
$testRoot = Join-Path $env:ProgramData "Roxy\KernelValidation\$([guid]::NewGuid().ToString('N'))"
$testFile = Join-Path $testRoot "ioctl-test.bin"
$ntTestRoot = "\??\$testRoot"
$ntTestFile = "\??\$testFile"
$registrySubkey = "SOFTWARE\Roxy\KernelValidation\$([guid]::NewGuid().ToString('N'))"
$registryNtPath = "\Registry\Machine\$registrySubkey"

function Add-StageResult([string]$Name, [bool]$Passed, [string]$Detail) {
    $stageResults.Add([ordered]@{
        name = $Name
        passed = $Passed
        detail = $Detail
    })
    $label = if ($Passed) { "PASS" } else { "FAIL" }
    Write-Host "[$label] $Name - $Detail"
}

function Assert-ByteArraysEqual([byte[]]$Actual, [byte[]]$Expected, [string]$Message) {
    if ($Actual.Length -ne $Expected.Length) { throw $Message }
    for ($i = 0; $i -lt $Actual.Length; $i++) {
        if ($Actual[$i] -ne $Expected[$i]) { throw $Message }
    }
}

function Set-UInt32([byte[]]$Buffer, [int]$Offset, [uint32]$Value) {
    [BitConverter]::GetBytes($Value).CopyTo($Buffer, $Offset)
}

function Set-UInt64([byte[]]$Buffer, [int]$Offset, [uint64]$Value) {
    [BitConverter]::GetBytes($Value).CopyTo($Buffer, $Offset)
}

function Set-Int64([byte[]]$Buffer, [int]$Offset, [int64]$Value) {
    [BitConverter]::GetBytes($Value).CopyTo($Buffer, $Offset)
}

function Set-FixedWideString(
    [byte[]]$Buffer,
    [int]$Offset,
    [int]$Capacity,
    [string]$Value,
    [switch]$NoTerminator
) {
    $encoded = [Text.Encoding]::Unicode.GetBytes($Value)
    $maximumBytes = if ($NoTerminator) { $Capacity * 2 } else { ($Capacity - 1) * 2 }
    if ($encoded.Length -gt $maximumBytes) {
        throw "Value exceeds the fixed UTF-16 field capacity."
    }
    [Array]::Copy($encoded, 0, $Buffer, $Offset, $encoded.Length)
}

function New-ReadMemoryInput([uint64]$ProcessId, [uint64]$Address, [uint32]$Size) {
    $buffer = [byte[]]::new(24)
    Set-UInt64 $buffer 0 $ProcessId
    Set-UInt64 $buffer 8 $Address
    Set-UInt32 $buffer 16 $Size
    return $buffer
}

function New-KillInput([uint64]$ProcessId) {
    return [BitConverter]::GetBytes($ProcessId)
}

function New-RegistryInput(
    [string]$KeyPath,
    [string]$ValueName,
    [uint32]$ValueType,
    [byte[]]$Data,
    [switch]$NoKeyTerminator,
    [switch]$NoValueTerminator,
    [uint32]$DeclaredDataSize = [uint32]::MaxValue
) {
    $headerSize = 1032
    $buffer = [byte[]]::new($headerSize + $Data.Length)
    Set-FixedWideString $buffer 0 256 $KeyPath -NoTerminator:$NoKeyTerminator
    Set-FixedWideString $buffer 512 256 $ValueName -NoTerminator:$NoValueTerminator
    Set-UInt32 $buffer 1024 $ValueType
    $size = if ($DeclaredDataSize -eq [uint32]::MaxValue) { [uint32]$Data.Length } else { $DeclaredDataSize }
    Set-UInt32 $buffer 1028 $size
    if ($Data.Length -gt 0) {
        [Array]::Copy($Data, 0, $buffer, $headerSize, $Data.Length)
    }
    return $buffer
}

function New-ListFilesInput([string]$Path, [switch]$NoTerminator) {
    $buffer = [byte[]]::new(1040)
    Set-FixedWideString $buffer 0 520 $Path -NoTerminator:$NoTerminator
    return $buffer
}

function New-FileInput(
    [string]$Path,
    [int64]$Offset,
    [uint32]$Length,
    [byte[]]$Data,
    [switch]$NoTerminator
) {
    $headerSize = 1056
    $buffer = [byte[]]::new($headerSize + $Data.Length)
    Set-FixedWideString $buffer 0 520 $Path -NoTerminator:$NoTerminator
    Set-Int64 $buffer 1040 $Offset
    Set-UInt32 $buffer 1048 $Length
    if ($Data.Length -gt 0) {
        [Array]::Copy($Data, 0, $buffer, $headerSize, $Data.Length)
    }
    return $buffer
}

function Open-Device {
    $handle = [KernelValidationNative]::CreateFile(
        "\\.\AIAgent",
        [Convert]::ToUInt32("C0000000", 16),
        [uint32]3,
        [IntPtr]::Zero,
        [uint32]3,
        [uint32]0,
        [IntPtr]::Zero
    )
    if ($handle.IsInvalid) {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $handle.Dispose()
        throw "Failed to open \\.\AIAgent (Win32 $errorCode)."
    }
    return $handle
}

function Invoke-RawIoctl(
    [string]$Name,
    [uint32]$Code,
    [byte[]]$Input,
    [int]$OutputSize,
    [bool]$ExpectSuccess,
    [scriptblock]$ValidateOutput
) {
    $output = if ($OutputSize -gt 0) { [byte[]]::new($OutputSize) } else { $null }
    $bytesReturned = 0
    $success = [KernelValidationNative]::DeviceIoControl(
        $device,
        $Code,
        $Input,
        $(if ($null -eq $Input) { 0 } else { $Input.Length }),
        $output,
        $OutputSize,
        [ref]$bytesReturned,
        [IntPtr]::Zero
    )
    $errorCode = if ($success) { 0 } else { [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
    $passed = $success -eq $ExpectSuccess
    $detail = "success=$success win32=$errorCode bytes=$bytesReturned"

    if ($passed -and $success -and $ValidateOutput) {
        try {
            & $ValidateOutput $output $bytesReturned
        } catch {
            $passed = $false
            $detail += " validation=$($_.Exception.Message)"
        }
    }

    $results.Add([ordered]@{
        name = $Name
        passed = $passed
        expectedSuccess = $ExpectSuccess
        success = $success
        win32Error = $errorCode
        bytesReturned = $bytesReturned
    })
    $label = if ($passed) { "PASS" } else { "FAIL" }
    Write-Host "  [$label] $Name ($detail)"

    if (-not $ExpectSuccess) {
        $healthOutput = [byte[]]::new(172)
        $healthBytes = 0
        $healthy = [KernelValidationNative]::DeviceIoControl(
            $device,
            $ioctls.ListProcesses,
            $null,
            0,
            $healthOutput,
            $healthOutput.Length,
            [ref]$healthBytes,
            [IntPtr]::Zero
        )
        if (-not $healthy) {
            $healthError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "Driver health probe failed after '$Name' (Win32 $healthError)."
        }
        if ($healthBytes -ne 172) {
            throw "Driver health probe returned $healthBytes bytes after '$Name'; expected 172."
        }
        $healthCount = [BitConverter]::ToUInt32($healthOutput, 0)
        if ($healthCount -ne 1) {
            throw "Driver health probe returned $healthCount process entries after '$Name'; expected 1."
        }
    }
}

function Invoke-Sc([string[]]$Arguments, [int[]]$AllowedExitCodes = @(0)) {
    $output = & sc.exe @Arguments 2>&1
    if ($LASTEXITCODE -notin $AllowedExitCodes) {
        throw "sc.exe $($Arguments -join ' ') failed with exit code $LASTEXITCODE`: $($output -join ' ')"
    }
    return $output
}

function Wait-ServiceState([string]$ExpectedState, [int]$TimeoutSeconds = 15) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $driver = Get-CimInstance Win32_SystemDriver -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
        if ($driver -and $driver.State -eq $ExpectedState) {
            return
        }
        Start-Sleep -Milliseconds 200
    } while ((Get-Date) -lt $deadline)
    $actual = if ($driver) { $driver.State } else { "missing" }
    throw "Service $ServiceName did not reach $ExpectedState; current state is $actual."
}

function Get-DumpFiles {
    $files = @()
    if (Test-Path -LiteralPath "$env:SystemRoot\MEMORY.DMP") {
        $files += Get-Item -LiteralPath "$env:SystemRoot\MEMORY.DMP"
    }
    if (Test-Path -LiteralPath "$env:SystemRoot\Minidump") {
        $files += Get-ChildItem -LiteralPath "$env:SystemRoot\Minidump" -Filter "*.dmp" -File
    }
    return @($files | ForEach-Object {
        [ordered]@{
            path = $_.FullName
            length = $_.Length
            lastWriteTimeUtc = $_.LastWriteTimeUtc.ToString("o")
        }
    })
}

function Get-NewDumpFiles([object[]]$Before, [object[]]$After) {
    return @($After | Where-Object {
        $candidate = $_
        -not ($Before | Where-Object {
            $_.path -eq $candidate.path -and $_.lastWriteTimeUtc -eq $candidate.lastWriteTimeUtc
        })
    })
}

function Export-ValidationEvidence {
    $systemLogPath = Join-Path $runDirectory "system-events.evtx"
    wevtutil.exe epl System $systemLogPath "/q:*[System[TimeCreated[@SystemTime>='$($runStartedAt.ToUniversalTime().ToString("o"))']]]" /ow:true
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $systemLogPath)) {
        throw "Failed to export the System event log for this validation run."
    }

    $dumpFilesAfter = Get-DumpFiles
    $dumpFilesAfter | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $runDirectory "dump-files-after.json") -Encoding UTF8
    return [ordered]@{
        systemLogPath = $systemLogPath
        dumpFilesAfter = $dumpFilesAfter
        newDumps = Get-NewDumpFiles $dumpFilesBefore $dumpFilesAfter
    }
}

function Remove-ValidationResources {
    if ($device) {
        $device.Dispose()
        $script:device = $null
    }
    if ($serviceCreated) {
        Invoke-Sc @("stop", $ServiceName) @(0, 1062) | Out-Null
        $script:driverLoaded = $false
        Invoke-Sc @("delete", $ServiceName) | Out-Null
        $deadline = (Get-Date).AddSeconds(15)
        do {
            $remainingService = Get-CimInstance Win32_SystemDriver -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
            if (-not $remainingService) { break }
            Start-Sleep -Milliseconds 200
        } while ((Get-Date) -lt $deadline)
        if ($remainingService) { throw "Validation service $ServiceName was not deleted." }
        $script:serviceCreated = $false
    }
    if (Test-Path -LiteralPath "HKLM:\$registrySubkey") {
        Remove-Item -LiteralPath "HKLM:\$registrySubkey" -Recurse -Force -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction Stop
    }
    foreach ($certificateStorePath in $addedCertificates) {
        if (Test-Path -LiteralPath $certificateStorePath) {
            Remove-Item -LiteralPath $certificateStorePath -Force -ErrorAction Stop
        }
    }
    $addedCertificates.Clear()
}

function Invoke-BridgeRequest([hashtable]$Request, [scriptblock]$ValidateResult) {
    $requestJson = $Request | ConvertTo-Json -Depth 10 -Compress
    $stderrPath = Join-Path $runDirectory "bridge-stderr-$([guid]::NewGuid().ToString('N')).log"
    $responseLines = $requestJson | & $BridgePath 2> $stderrPath
    if ($LASTEXITCODE -ne 0) {
        $stderr = Get-Content -Raw -LiteralPath $stderrPath -ErrorAction SilentlyContinue
        throw "Bridge exited with $LASTEXITCODE`: $stderr"
    }
    $responseLine = @($responseLines | Where-Object { $_ -match '^\s*\{' })
    if ($responseLine.Count -ne 1) {
        throw "Bridge did not return exactly one JSON response."
    }
    $response = $responseLine[0] | ConvertFrom-Json
    $errorProperty = $response.PSObject.Properties["error"]
    if ($response.jsonrpc -ne "2.0" -or $response.id -ne $Request.id) {
        throw "Bridge returned an invalid JSON-RPC version or response ID."
    }
    if ($errorProperty -and $errorProperty.Value) {
        throw "Bridge error $($errorProperty.Value.code): $($errorProperty.Value.message)"
    }
    if (-not $response.PSObject.Properties["result"]) {
        throw "Bridge response is missing result."
    }
    if ($ValidateResult) { & $ValidateResult $response.result }
    return $response
}

function ConvertFrom-BridgeToolResult($Result) {
    if ($Result.content.Count -ne 1 -or $Result.content[0].type -ne "text") {
        throw "Bridge tool response has an invalid MCP content envelope."
    }
    return $Result.content[0].text | ConvertFrom-Json
}

function Invoke-BridgeExpectedError([hashtable]$Request) {
    $requestJson = $Request | ConvertTo-Json -Depth 10 -Compress
    $stderrPath = Join-Path $runDirectory "bridge-stderr-$([guid]::NewGuid().ToString('N')).log"
    $responseLines = $requestJson | & $BridgePath 2> $stderrPath
    if ($LASTEXITCODE -ne 0) {
        throw "Bridge process crashed while handling an expected tool error."
    }
    $responseLine = @($responseLines | Where-Object { $_ -match '^\s*\{' })
    if ($responseLine.Count -ne 1) {
        throw "Bridge did not return exactly one JSON error response."
    }
    $response = $responseLine[0] | ConvertFrom-Json
    if ($response.jsonrpc -ne "2.0" -or $response.id -ne $Request.id) {
        throw "Bridge returned an invalid JSON-RPC version or response ID."
    }
    $errorProperty = $response.PSObject.Properties["error"]
    if (-not $errorProperty -or -not $errorProperty.Value) {
        throw "Bridge request unexpectedly succeeded."
    }
}

try {
    Start-Transcript -Path $logPath -Force | Out-Null
    $transcriptStarted = $true

    $dumpConfigurationBefore = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"
    $dumpFilesBefore = Get-DumpFiles
    $dumpConfigurationBefore | Select-Object CrashDumpEnabled, DumpFile, MinidumpDir, Overwrite, AutoReboot, AlwaysKeepMemoryDump |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $runDirectory "crash-control-before.json") -Encoding UTF8
    $dumpFilesBefore | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $runDirectory "dump-files-before.json") -Encoding UTF8

    if ($ConfigureKernelDumps) {
        $crashControl = "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"
        New-ItemProperty -LiteralPath $crashControl -Name CrashDumpEnabled -PropertyType DWord -Value 2 -Force | Out-Null
        New-ItemProperty -LiteralPath $crashControl -Name DumpFile -PropertyType ExpandString -Value "%SystemRoot%\MEMORY.DMP" -Force | Out-Null
        New-ItemProperty -LiteralPath $crashControl -Name MinidumpDir -PropertyType ExpandString -Value "%SystemRoot%\Minidump" -Force | Out-Null
        New-ItemProperty -LiteralPath $crashControl -Name Overwrite -PropertyType DWord -Value 1 -Force | Out-Null
        New-ItemProperty -LiteralPath $crashControl -Name AlwaysKeepMemoryDump -PropertyType DWord -Value 1 -Force | Out-Null
        New-ItemProperty -LiteralPath $crashControl -Name AutoReboot -PropertyType DWord -Value 0 -Force | Out-Null
        Add-StageResult "crash-dump-configuration" $true "Kernel-memory dumps configured at %SystemRoot%\MEMORY.DMP; automatic reboot disabled."
    } else {
        Add-StageResult "crash-dump-configuration" $true "Existing crash-dump settings recorded; pass -ConfigureKernelDumps to require a kernel-memory dump."
    }

    if ($CertificatePath) {
        $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificatePath)
        foreach ($storeName in @("Root", "TrustedPublisher")) {
            $storePath = "Cert:\LocalMachine\$storeName\$($certificate.Thumbprint)"
            if (-not (Test-Path -LiteralPath $storePath)) {
                Import-Certificate -FilePath $CertificatePath -CertStoreLocation "Cert:\LocalMachine\$storeName" | Out-Null
                $addedCertificates.Add($storePath)
            }
        }
        Add-StageResult "test-certificate" $true "Driver signer is trusted for this validation run."
    }

    $existing = Get-CimInstance Win32_SystemDriver -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
    if ($existing) {
        throw "Refusing to reuse existing service $ServiceName. Remove it or choose another -ServiceName."
    }

    Invoke-Sc @("create", $ServiceName, "type=", "kernel", "start=", "demand", "binPath=", $DriverPath) | Out-Null
    $serviceCreated = $true

    for ($cycle = 1; $cycle -le $LoadCycles; $cycle++) {
        Invoke-Sc @("start", $ServiceName) | Out-Null
        $driverLoaded = $true
        Wait-ServiceState "Running"
        $cycleDevice = Open-Device
        $cycleDevice.Dispose()
        Invoke-Sc @("stop", $ServiceName) | Out-Null
        Wait-ServiceState "Stopped"
        $driverLoaded = $false
        $cycleDumps = Get-DumpFiles
        $changedCycleDumps = @($cycleDumps | Where-Object {
            $candidate = $_
            -not ($dumpFilesBefore | Where-Object { $_.path -eq $candidate.path -and $_.lastWriteTimeUtc -eq $candidate.lastWriteTimeUtc })
        })
        if ($changedCycleDumps.Count -gt 0) {
            throw "A crash dump was created or changed during load/unload cycle $cycle."
        }
        $systemEvents = @(Get-WinEvent -FilterHashtable @{
            LogName = "System"
            ProviderName = "Service Control Manager"
            StartTime = $runStartedAt
        } -ErrorAction Stop | Where-Object {
            $_.Message -like "*$ServiceName*" -and $_.LevelDisplayName -in @("Critical", "Error")
        })
        if ($systemEvents.Count -gt 0) {
            throw "System log contains a driver service error during load/unload cycle $cycle."
        }
        Write-Host "  [PASS] load/unload cycle $cycle/$LoadCycles"
    }
    Add-StageResult "load-unload" $true "$LoadCycles load/open/unload cycles completed."

    Invoke-Sc @("start", $ServiceName) | Out-Null
    $driverLoaded = $true
    Wait-ServiceState "Running"
    $device = Open-Device

    New-Item -ItemType Directory -Force -Path $testRoot | Out-Null
    [IO.File]::WriteAllBytes($testFile, [Text.Encoding]::UTF8.GetBytes("seed-data"))
    New-Item -Path "HKLM:\$registrySubkey" -Force | Out-Null

    Write-Host "=== Raw IOCTL validation ==="
    $memory = [Runtime.InteropServices.Marshal]::AllocHGlobal(65536)
    try {
        $memoryData = [byte[]]::new(65536)
        for ($i = 0; $i -lt $memoryData.Length; $i++) { $memoryData[$i] = [byte]($i % 251) }
        [Runtime.InteropServices.Marshal]::Copy($memoryData, 0, $memory, $memoryData.Length)
        $pid = [uint64]$PID
        $address = [uint64]$memory.ToInt64()
        Invoke-RawIoctl "read-memory-valid" $ioctls.ReadProcessMemory (New-ReadMemoryInput $pid $address 16) 16 $true {
            param($output, $count)
            if ($count -ne 16) { throw "Expected 16 bytes." }
            Assert-ByteArraysEqual $output ([byte[]]$memoryData[0..15]) "Process-memory data did not match the source buffer."
        }
        Invoke-RawIoctl "read-memory-boundary-65536" $ioctls.ReadProcessMemory (New-ReadMemoryInput $pid $address 65536) 65536 $true {
        param($output, $count)
        if ($count -ne 65536) { throw "Expected 65536 bytes." }
        Assert-ByteArraysEqual $output $memoryData "Boundary process-memory data did not match the source buffer."
    }
        Invoke-RawIoctl "read-memory-oversized-length" $ioctls.ReadProcessMemory (New-ReadMemoryInput $pid $address 65537) 65537 $false $null
        Invoke-RawIoctl "read-memory-truncated-input" $ioctls.ReadProcessMemory ([byte[]]::new(23)) 16 $false $null
        Invoke-RawIoctl "read-memory-malformed-address" $ioctls.ReadProcessMemory (New-ReadMemoryInput $pid ([uint64]::MaxValue) 16) 16 $false $null
    } finally {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($memory)
    }

    Invoke-RawIoctl "list-processes-valid" $ioctls.ListProcesses $null (4 + 4096 * 168) $true {
        param($output, $count)
        if ($count -lt 172) { throw "Expected at least one process entry." }
    }
    Invoke-RawIoctl "list-processes-boundary-output" $ioctls.ListProcesses $null 172 $true {
        param($output, $count)
        if ($count -ne 172 -or [BitConverter]::ToUInt32($output, 0) -ne 1) {
            throw "Expected one complete process entry."
        }
    }
    Invoke-RawIoctl "list-processes-oversized-input" $ioctls.ListProcesses ([byte[]]::new(1)) 172 $false $null
    Invoke-RawIoctl "list-processes-truncated-output" $ioctls.ListProcesses $null 171 $false $null
    Invoke-RawIoctl "list-processes-malformed-ioctl" ([Convert]::ToUInt32("800060FC", 16)) $null 172 $false $null

    $killTarget = Start-Process "$env:SystemRoot\System32\cmd.exe" -ArgumentList "/d", "/c", "ping -n 120 127.0.0.1 >nul" -WindowStyle Hidden -PassThru
    try {
        Invoke-RawIoctl "kill-process-valid-owned-target" $ioctls.KillProcess (New-KillInput ([uint64]$killTarget.Id)) 4 $true {
        param($output, $count)
        if ($count -ne 4 -or [BitConverter]::ToInt32($output, 0) -lt 0) {
            throw "Expected a successful four-byte status response."
        }
    }
        $killTarget.WaitForExit(5000) | Out-Null
        if (-not $killTarget.HasExited) { throw "Owned kill target did not exit." }
    } finally {
        if (-not $killTarget.HasExited) { Stop-Process -Id $killTarget.Id -Force -ErrorAction SilentlyContinue }
        $killTarget.Dispose()
    }
    Invoke-RawIoctl "kill-process-boundary-invalid-pid" $ioctls.KillProcess (New-KillInput ([uint64]::MaxValue)) 4 $false $null
    Invoke-RawIoctl "kill-process-oversized-input" $ioctls.KillProcess ([byte[]]::new(9)) 4 $false $null
    Invoke-RawIoctl "kill-process-truncated-input" $ioctls.KillProcess ([byte[]]::new(7)) 4 $false $null
    Invoke-RawIoctl "kill-process-malformed-zero-pid" $ioctls.KillProcess (New-KillInput 0) 4 $false $null

    $smallRegistryData = [BitConverter]::GetBytes([uint32]0x12345678)
    $maxRegistryData = [byte[]]::new(4096)
    for ($i = 0; $i -lt $maxRegistryData.Length; $i++) { $maxRegistryData[$i] = [byte]($i % 239) }
    Invoke-RawIoctl "write-registry-valid" $ioctls.WriteRegistry (New-RegistryInput $registryNtPath "Small" 4 $smallRegistryData) 4 $true {
        param($output, $count)
        if ($count -ne 4 -or [BitConverter]::ToInt32($output, 0) -lt 0) {
            throw "Expected a successful four-byte status response."
        }
    }
    Invoke-RawIoctl "write-registry-boundary-4096" $ioctls.WriteRegistry (New-RegistryInput $registryNtPath "Maximum" 3 $maxRegistryData) 4 $true {
        param($output, $count)
        if ($count -ne 4 -or [BitConverter]::ToInt32($output, 0) -lt 0) {
            throw "Expected a successful four-byte status response."
        }
    }
    Invoke-RawIoctl "write-registry-oversized-data" $ioctls.WriteRegistry (New-RegistryInput $registryNtPath "Oversized" 3 ([byte[]]::new(4097))) 4 $false $null
    Invoke-RawIoctl "write-registry-truncated-data" $ioctls.WriteRegistry (New-RegistryInput $registryNtPath "Truncated" 3 ([byte[]]::new(3)) -DeclaredDataSize 4) 4 $false $null
    Invoke-RawIoctl "write-registry-malformed-unterminated-key" $ioctls.WriteRegistry (New-RegistryInput ("K" * 256) "Bad" 3 ([byte[]]::new(0)) -NoKeyTerminator) 4 $false $null

    Invoke-RawIoctl "read-registry-valid" $ioctls.ReadRegistry (New-RegistryInput $registryNtPath "Small" 0 ([byte[]]::new(0))) 4104 $true {
        param($output, $count)
        if ($count -ne 12) { throw "Expected 8-byte header and 4-byte value." }
        if ([BitConverter]::ToUInt32($output, 0) -ne 4 -or [BitConverter]::ToUInt32($output, 4) -ne 4) {
            throw "Registry response header did not match REG_DWORD data."
        }
        Assert-ByteArraysEqual ([byte[]]$output[8..11]) $smallRegistryData "Registry response data did not match the written value."
    }
    Invoke-RawIoctl "read-registry-boundary-4096" $ioctls.ReadRegistry (New-RegistryInput $registryNtPath "Maximum" 0 ([byte[]]::new(0))) 4104 $true {
        param($output, $count)
        if ($count -ne 4104 -or [BitConverter]::ToUInt32($output, 4) -ne 4096) {
            throw "Expected a complete 4096-byte registry value."
        }
        Assert-ByteArraysEqual ([byte[]]$output[8..4103]) $maxRegistryData "Boundary registry data did not match the written value."
    }
    Invoke-RawIoctl "read-registry-boundary-header-output" $ioctls.ReadRegistry (New-RegistryInput $registryNtPath "Small" 0 ([byte[]]::new(0))) 8 $false $null
    $readRegistryOversized = New-RegistryInput $registryNtPath "Small" 0 ([byte[]]::new(1))
    Invoke-RawIoctl "read-registry-oversized-input" $ioctls.ReadRegistry $readRegistryOversized 4104 $false $null
    Invoke-RawIoctl "read-registry-truncated-input" $ioctls.ReadRegistry ([byte[]]::new(1031)) 4104 $false $null
    Invoke-RawIoctl "read-registry-malformed-unterminated-key" $ioctls.ReadRegistry (New-RegistryInput ("R" * 256) "Bad" 0 ([byte[]]::new(0)) -NoKeyTerminator) 4104 $false $null

    Invoke-RawIoctl "list-files-valid" $ioctls.ListFiles (New-ListFilesInput $ntTestRoot) (4 + 16 * 1080) $true $null
    Invoke-RawIoctl "list-files-boundary-one-entry" $ioctls.ListFiles (New-ListFilesInput $ntTestRoot) 1084 $true {
        param($output, $count)
        if ($count -ne 1084 -or [BitConverter]::ToUInt32($output, 0) -ne 1) {
            throw "Expected one complete file entry."
        }
    }
    $listFilesOversized = [byte[]]::new(1041)
    [Array]::Copy((New-ListFilesInput $ntTestRoot), $listFilesOversized, 1040)
    Invoke-RawIoctl "list-files-oversized-input" $ioctls.ListFiles $listFilesOversized 1084 $false $null
    Invoke-RawIoctl "list-files-truncated-input" $ioctls.ListFiles ([byte[]]::new(1039)) 1084 $false $null
    Invoke-RawIoctl "list-files-malformed-unterminated-path" $ioctls.ListFiles (New-ListFilesInput ("P" * 520) -NoTerminator) 1084 $false $null

    $smallFileData = [Text.Encoding]::UTF8.GetBytes("kernel-write-test")
    Invoke-RawIoctl "write-file-boundary-empty" $ioctls.WriteFile (New-FileInput $ntTestFile 0 0 ([byte[]]::new(0))) 4 $true {
        param($output, $count)
        if ($count -ne 4 -or [BitConverter]::ToInt32($output, 0) -lt 0) {
            throw "Expected a successful four-byte status response."
        }
    }
    $maxFileData = [byte[]]::new(65536)
    for ($i = 0; $i -lt $maxFileData.Length; $i++) { $maxFileData[$i] = [byte]($i % 233) }
    Invoke-RawIoctl "write-file-valid" $ioctls.WriteFile (New-FileInput $ntTestFile 0 $smallFileData.Length $smallFileData) 4 $true {
        param($output, $count)
        if ($count -ne 4 -or [BitConverter]::ToInt32($output, 0) -lt 0) {
            throw "Expected a successful four-byte status response."
        }
    }
    Invoke-RawIoctl "write-file-boundary-65536" $ioctls.WriteFile (New-FileInput $ntTestFile 0 65536 $maxFileData) 4 $true {
        param($output, $count)
        if ($count -ne 4 -or [BitConverter]::ToInt32($output, 0) -lt 0) {
            throw "Expected a successful four-byte status response."
        }
    }
    Invoke-RawIoctl "write-file-oversized-length" $ioctls.WriteFile (New-FileInput $ntTestFile 0 65537 ([byte[]]::new(65537))) 4 $false $null
    Invoke-RawIoctl "write-file-truncated-data" $ioctls.WriteFile (New-FileInput $ntTestFile 0 4 ([byte[]]::new(3))) 4 $false $null
    Invoke-RawIoctl "write-file-malformed-unterminated-path" $ioctls.WriteFile (New-FileInput ("F" * 520) 0 0 ([byte[]]::new(0)) -NoTerminator) 4 $false $null

    Invoke-RawIoctl "read-file-valid" $ioctls.ReadFile (New-FileInput $ntTestFile 0 16 ([byte[]]::new(0))) 16 $true {
        param($output, $count)
        if ($count -ne 16) { throw "Expected 16 bytes." }
        Assert-ByteArraysEqual $output ([byte[]]$maxFileData[0..15]) "File data did not match the written boundary payload."
    }
    Invoke-RawIoctl "read-file-boundary-zero" $ioctls.ReadFile (New-FileInput $ntTestFile 0 0 ([byte[]]::new(0))) 0 $false $null
    Invoke-RawIoctl "read-file-boundary-65536" $ioctls.ReadFile (New-FileInput $ntTestFile 0 65536 ([byte[]]::new(0))) 65536 $true {
        param($output, $count)
        if ($count -ne 65536) { throw "Expected 65536 bytes." }
        Assert-ByteArraysEqual $output $maxFileData "Boundary file data did not match the written payload."
    }
    Invoke-RawIoctl "read-file-oversized-length" $ioctls.ReadFile (New-FileInput $ntTestFile 0 65537 ([byte[]]::new(0))) 65537 $false $null
    Invoke-RawIoctl "read-file-truncated-input" $ioctls.ReadFile ([byte[]]::new(1055)) 16 $false $null
    Invoke-RawIoctl "read-file-malformed-unterminated-path" $ioctls.ReadFile (New-FileInput ("F" * 520) 0 16 ([byte[]]::new(0)) -NoTerminator) 16 $false $null

    $rawPassed = @($results | Where-Object { -not $_.passed }).Count -eq 0
    Add-StageResult "raw-ioctl-matrix" $rawPassed "$($results.Count) valid, boundary, oversized, truncated, and malformed cases completed."
    if (-not $rawPassed) { throw "Raw IOCTL validation failed." }

    $device.Dispose()
    $device = $null

    Write-Host "=== Direct Rust bridge validation ==="
    Invoke-BridgeRequest @{ jsonrpc = "2.0"; id = 1; method = "initialize"; params = @{} } {
        param($result)
        if ($result.serverInfo.name -ne "roxy-kernel-bridge") { throw "Unexpected bridge server identity." }
    } | Out-Null
    Invoke-BridgeRequest @{ jsonrpc = "2.0"; id = 2; method = "tools/list"; params = @{} } {
        param($result)
        if ($result.tools.Count -ne 8) { throw "Bridge did not advertise all eight tools." }
    } | Out-Null

    $bridgeMemory = [Runtime.InteropServices.Marshal]::AllocHGlobal(16)
    try {
        $bridgeMemoryData = [byte[]](11, 22, 33, 44, 55, 66, 77, 88, 99, 111, 122, 133, 144, 155, 166, 177)
        [Runtime.InteropServices.Marshal]::Copy($bridgeMemoryData, 0, $bridgeMemory, $bridgeMemoryData.Length)
        Invoke-BridgeRequest @{ jsonrpc = "2.0"; id = 3; method = "tools/call"; params = @{ name = "read_process_memory"; arguments = @{ pid = $PID; address = [uint64]$bridgeMemory.ToInt64(); size = 16 } } } {
            param($result)
            $payload = ConvertFrom-BridgeToolResult $result
            if ($payload.bytes_read -ne 16 -or $payload.data_base64 -ne [Convert]::ToBase64String($bridgeMemoryData)) {
                throw "Bridge process-memory result did not match the source buffer."
            }
        } | Out-Null
    } finally {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($bridgeMemory)
    }

    Invoke-BridgeRequest @{ jsonrpc = "2.0"; id = 4; method = "tools/call"; params = @{ name = "list_processes"; arguments = @{} } } {
        param($result)
        $payload = ConvertFrom-BridgeToolResult $result
        if ($payload.count -lt 1) { throw "Bridge returned no processes." }
    } | Out-Null

    $bridgeRegistryData = [byte[]](1, 2, 3, 4)
    Invoke-BridgeRequest @{ jsonrpc = "2.0"; id = 5; method = "tools/call"; params = @{ name = "write_registry"; arguments = @{ key_path = $registryNtPath; value_name = "Bridge"; value_type = 3; data = [Convert]::ToBase64String($bridgeRegistryData) } } } {
        param($result)
        $payload = ConvertFrom-BridgeToolResult $result
        if (-not $payload.success) { throw "Bridge registry write reported failure." }
    } | Out-Null
    Invoke-BridgeRequest @{ jsonrpc = "2.0"; id = 6; method = "tools/call"; params = @{ name = "read_registry"; arguments = @{ key_path = $registryNtPath; value_name = "Bridge" } } } {
        param($result)
        $payload = ConvertFrom-BridgeToolResult $result
        if ($payload.value_type -ne 3 -or $payload.data_base64 -ne [Convert]::ToBase64String($bridgeRegistryData)) {
            throw "Bridge registry read did not match the written data."
        }
    } | Out-Null

    Invoke-BridgeRequest @{ jsonrpc = "2.0"; id = 7; method = "tools/call"; params = @{ name = "list_files"; arguments = @{ path = $ntTestRoot } } } {
        param($result)
        $payload = ConvertFrom-BridgeToolResult $result
        if ($payload.count -lt 1) { throw "Bridge returned no files from the disposable directory." }
    } | Out-Null
    $bridgeFileData = [Text.Encoding]::UTF8.GetBytes("bridge-write")
    Invoke-BridgeRequest @{ jsonrpc = "2.0"; id = 8; method = "tools/call"; params = @{ name = "write_file"; arguments = @{ path = $ntTestFile; offset = 0; data = [Convert]::ToBase64String($bridgeFileData) } } } {
        param($result)
        $payload = ConvertFrom-BridgeToolResult $result
        if (-not $payload.success -or $payload.bytes_written -ne $bridgeFileData.Length) {
            throw "Bridge file write reported an invalid result."
        }
    } | Out-Null
    Invoke-BridgeRequest @{ jsonrpc = "2.0"; id = 9; method = "tools/call"; params = @{ name = "read_file"; arguments = @{ path = $ntTestFile; offset = 0; length = $bridgeFileData.Length } } } {
        param($result)
        $payload = ConvertFrom-BridgeToolResult $result
        if ($payload.data_base64 -ne [Convert]::ToBase64String($bridgeFileData)) {
            throw "Bridge file read did not match the written data."
        }
    } | Out-Null

    $bridgeKillTarget = Start-Process "$env:SystemRoot\System32\cmd.exe" -ArgumentList "/d", "/c", "ping -n 120 127.0.0.1 >nul" -WindowStyle Hidden -PassThru
    try {
        Invoke-BridgeRequest @{ jsonrpc = "2.0"; id = 10; method = "tools/call"; params = @{ name = "kill_process"; arguments = @{ pid = $bridgeKillTarget.Id } } } {
            param($result)
            $payload = ConvertFrom-BridgeToolResult $result
            if (-not $payload.success) { throw "Bridge process termination reported failure." }
        } | Out-Null
        $bridgeKillTarget.WaitForExit(5000) | Out-Null
        if (-not $bridgeKillTarget.HasExited) { throw "Bridge kill target did not exit." }
    } finally {
        if (-not $bridgeKillTarget.HasExited) { Stop-Process -Id $bridgeKillTarget.Id -Force -ErrorAction SilentlyContinue }
        $bridgeKillTarget.Dispose()
    }
    Invoke-BridgeExpectedError @{ jsonrpc = "2.0"; id = 11; method = "tools/call"; params = @{ name = "read_process_memory"; arguments = @{ pid = [uint64]::MaxValue; address = 0; size = 16 } } }
    Invoke-BridgeExpectedError @{ jsonrpc = "2.0"; id = 12; method = "tools/call"; params = @{ name = "read_file"; arguments = @{ path = $ntTestFile; length = 0 } } }
    Invoke-BridgeExpectedError @{ jsonrpc = "2.0"; id = 13; method = "tools/call"; params = @{ name = "read_file"; arguments = @{ path = $ntTestFile; length = "invalid" } } }
    Invoke-BridgeExpectedError @{ jsonrpc = "2.0"; id = 14; method = "tools/call"; params = @{ name = "write_registry"; arguments = @{ key_path = $registryNtPath; value_name = "Invalid"; value_type = "invalid"; data = "" } } }
    Add-StageResult "direct-rust-bridge" $true "All eight bridge tools succeeded directly on disposable targets; invalid calls returned JSON-RPC errors without MCP registration."

    Invoke-Sc @("stop", $ServiceName) | Out-Null
    Wait-ServiceState "Stopped"
    $driverLoaded = $false
    Add-StageResult "final-unload" $true "Driver stopped cleanly after raw and direct bridge tests."

    Remove-ValidationResources
    Add-StageResult "resource-cleanup" $true "Validation service, disposable targets, and Roxy-added certificate trust were removed."

    $evidence = Export-ValidationEvidence
    $newDumps = $evidence.newDumps
    Add-StageResult "no-new-crash-dumps" ($newDumps.Count -eq 0) $(if ($newDumps.Count -eq 0) { "No dump was created or changed during validation." } else { "$($newDumps.Count) dump file(s) were created or changed." })

    $allPassed = @($stageResults | Where-Object { -not $_.passed }).Count -eq 0
    $gate = [ordered]@{
        schemaVersion = 1
        generatedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
        mcpEligible = $allPassed
        driver = [ordered]@{
            path = $DriverPath
            sha256 = (Get-FileHash -LiteralPath $DriverPath -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        bridge = [ordered]@{
            path = $BridgePath
            sha256 = (Get-FileHash -LiteralPath $BridgePath -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        loadCycles = $LoadCycles
        reportPath = $reportPath
    }
    $report = [ordered]@{
        schemaVersion = 1
        startedAtUtc = (Get-Item -LiteralPath $logPath).CreationTimeUtc.ToString("o")
        completedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
        computerName = $env:COMPUTERNAME
        serviceName = $ServiceName
        testRoot = $testRoot
        stageResults = $stageResults
        ioctlResults = $results
        newDumps = $newDumps
        systemLogPath = $evidence.systemLogPath
        mcpEligibility = $gate
    }
    if (-not $allPassed) { throw "One or more validation stages failed; MCP remains ineligible." }
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $reportPath -Encoding UTF8
    $gate | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $gatePath -Encoding UTF8
    Write-Host "Validation passed. MCP eligibility report: $gatePath"
} catch {
    $validationError = $_
    Add-StageResult "validation-run" $false $validationError.Exception.Message

    $cleanupErrors = [System.Collections.Generic.List[string]]::new()
    try { Remove-ValidationResources } catch { $cleanupErrors.Add($_.Exception.Message) }

    $failureEvidence = $null
    try { $failureEvidence = Export-ValidationEvidence } catch { $cleanupErrors.Add($_.Exception.Message) }

    $failureGate = [ordered]@{
        schemaVersion = 1
        generatedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
        mcpEligible = $false
        driver = [ordered]@{
            path = $DriverPath
            sha256 = (Get-FileHash -LiteralPath $DriverPath -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        bridge = [ordered]@{
            path = $BridgePath
            sha256 = (Get-FileHash -LiteralPath $BridgePath -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        reportPath = $reportPath
    }
    $failureGate | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $gatePath -Encoding UTF8

    $failureReport = [ordered]@{
        schemaVersion = 1
        completedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
        error = $validationError.Exception.ToString()
        cleanupErrors = $cleanupErrors
        stageResults = $stageResults
        ioctlResults = $results
        newDumps = if ($failureEvidence) { $failureEvidence.newDumps } else { @() }
        systemLogPath = if ($failureEvidence) { $failureEvidence.systemLogPath } else { $null }
        mcpEligibility = $failureGate
    }
    $failureReport | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $reportPath -Encoding UTF8
    throw $validationError
} finally {
    if ($transcriptStarted) { Stop-Transcript | Out-Null }
}
