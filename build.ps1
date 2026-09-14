param(
    [string]$Version = "dev",
    [switch]$TestSign
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$out = Join-Path $root "out"
$dist = Join-Path $root "dist"
$package = Join-Path $dist "package"
$symbols = Join-Path $dist "symbols"

function Find-WdkTool([string]$Name) {
    $kitsRoot = "${env:ProgramFiles(x86)}\Windows Kits\10"
    $tool = Get-ChildItem $kitsRoot -Filter $Name -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match "\\x64\\" } |
        Sort-Object FullName -Descending |
        Select-Object -First 1
    if (-not $tool) {
        throw "$Name was not found. Install the Windows Driver Kit with Visual Studio integration."
    }
    return $tool.FullName
}

Remove-Item $out, $dist -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $out, $package, $symbols | Out-Null

& (Join-Path $root "driver\build.ps1")
if ($LASTEXITCODE -ne 0) { throw "Driver build failed." }

& cargo fmt --manifest-path (Join-Path $root "bridge\Cargo.toml") -- --check
if ($LASTEXITCODE -ne 0) { throw "cargo fmt failed." }
& cargo test --manifest-path (Join-Path $root "bridge\Cargo.toml") --locked
if ($LASTEXITCODE -ne 0) { throw "cargo test failed." }
& cargo clippy --manifest-path (Join-Path $root "bridge\Cargo.toml") --locked --bin roxy-kernel-bridge -- -D warnings
if ($LASTEXITCODE -ne 0) { throw "cargo clippy failed." }
& (Join-Path $root "bridge\build.ps1")
if ($LASTEXITCODE -ne 0) { throw "Bridge build failed." }

$driver = Join-Path $out "aibridge.sys"
$bridge = Join-Path $out "roxy-kernel-bridge.exe"
Copy-Item $driver, $bridge -Destination $package

$certificate = $null
if ($TestSign) {
    $certificate = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject "CN=Roxy Kernel Tools Test Signing" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyAlgorithm RSA `
        -KeyLength 3072 `
        -HashAlgorithm SHA256 `
        -KeyExportPolicy Exportable `
        -NotAfter (Get-Date).AddYears(3)

    $signTool = Find-WdkTool "signtool.exe"
    & $signTool sign /v /fd SHA256 /s My /sha1 $certificate.Thumbprint (Join-Path $package "aibridge.sys")
    if ($LASTEXITCODE -ne 0) { throw "Driver signing failed." }
    Export-Certificate -Cert $certificate -FilePath (Join-Path $package "aibridge-test.cer") | Out-Null
}

if ($TestSign) {
    $signTool = Find-WdkTool "signtool.exe"
    $rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "CurrentUser")
    $publisherStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("TrustedPublisher", "CurrentUser")
    try {
        $rootStore.Open("ReadWrite")
        $publisherStore.Open("ReadWrite")
        $rootStore.Add($certificate)
        $publisherStore.Add($certificate)
        & $signTool verify /v /pa (Join-Path $package "aibridge.sys")
        if ($LASTEXITCODE -ne 0) { throw "Driver signature verification failed." }
    } finally {
        if ($rootStore.IsOpen) { $rootStore.Remove($certificate) }
        if ($publisherStore.IsOpen) { $publisherStore.Remove($certificate) }
        $rootStore.Close()
        $publisherStore.Close()
        Remove-Item "Cert:\CurrentUser\My\$($certificate.Thumbprint)" -Force -ErrorAction SilentlyContinue
    }
}

$sourceCommit = (& git -C $root rev-parse HEAD).Trim()
$fileRecords = Get-ChildItem $package -File | Sort-Object Name | ForEach-Object {
    [ordered]@{
        name = $_.Name
        size = $_.Length
        sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}
$manifest = [ordered]@{
    version = $Version
    architecture = "x64"
    sourceCommit = $sourceCommit
    testSigned = [bool]$TestSign
    signerThumbprint = if ($certificate) { $certificate.Thumbprint.ToLowerInvariant() } else { $null }
    files = @($fileRecords)
}
$manifest | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $package "manifest.json") -Encoding UTF8

$driverPdb = Get-ChildItem (Join-Path $root "driver\x64\Release") -Filter "aibridge.pdb" -Recurse | Select-Object -First 1
$bridgePdb = Join-Path $root "bridge\target\release\roxy_kernel_bridge.pdb"
if ($driverPdb) { Copy-Item $driverPdb.FullName $symbols }
if (Test-Path $bridgePdb) { Copy-Item $bridgePdb $symbols }

$packageZip = Join-Path $dist "kernel-tools-windows-x64.zip"
$symbolsZip = Join-Path $dist "kernel-tools-symbols-windows-x64.zip"
Compress-Archive -Path (Join-Path $package "*") -DestinationPath $packageZip -CompressionLevel Optimal
if (Get-ChildItem $symbols -File) {
    Compress-Archive -Path (Join-Path $symbols "*") -DestinationPath $symbolsZip -CompressionLevel Optimal
}

$checksumLines = Get-ChildItem $dist -Filter "*.zip" | Sort-Object Name | ForEach-Object {
    "$((Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant())  $($_.Name)"
}
$checksumLines | Set-Content (Join-Path $dist "checksums.sha256") -Encoding ASCII
Write-Host "Built release artifacts in $dist"
