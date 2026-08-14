# SPDX-License-Identifier: MIT OR Apache-2.0

[CmdletBinding()]
param(
    [switch]$Force,
    [switch]$NoModifyPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Version = '0.1.0-alpha.1'
$ArchiveUrl = 'https://github.com/sharkone/membridge/releases/download/v0.1.0-alpha.1/membridge-x86_64-pc-windows-msvc.zip'
$ArchiveSha256 = '9df5a98f4964c67a6fd87535d903fe1e1574c63ab0ffc1634858ef1cc13155e7'
$MaxArchiveBytes = 20MB

if ($PSVersionTable.PSVersion.Major -lt 5) {
    throw 'this bootstrap script requires PowerShell 5 or later'
}

if (-not $Force) {
    $Command = Get-Command membridge -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($Command) {
        $InstalledVersion = & $Command.Path --version 2>$null
        if ($LASTEXITCODE -eq 0 -and $InstalledVersion -eq "membridge $Version") {
            Write-Output "membridge $Version is already installed"
            return
        }
    }
}

if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) {
    throw 'this bootstrap script supports Windows only'
}

$Architecture = if ($env:PROCESSOR_ARCHITEW6432) {
    $env:PROCESSOR_ARCHITEW6432
} else {
    $env:PROCESSOR_ARCHITECTURE
}
if ($Architecture -notin @('AMD64', 'ARM64')) {
    throw \"this release requires x64 Windows; detected architecture: $Architecture\"
}

$CargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $HOME '.cargo' }
$CargoHome = [IO.Path]::GetFullPath($CargoHome)
$InstallDirectory = Join-Path $CargoHome 'bin'
$Destination = Join-Path $InstallDirectory 'membridge.exe'
$TemporaryDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("membridge-bootstrap-{0}" -f [Guid]::NewGuid().ToString('N'))
$Archive = Join-Path $TemporaryDirectory 'membridge.zip'
$Extracted = Join-Path $TemporaryDirectory 'extracted'
$Staging = Join-Path $InstallDirectory (".membridge-{0}.exe" -f [Guid]::NewGuid().ToString('N'))
$PreviousSecurityProtocol = [Net.ServicePointManager]::SecurityProtocol

try {
    New-Item -ItemType Directory -Path $TemporaryDirectory | Out-Null
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -UseBasicParsing -Uri $ArchiveUrl -OutFile $Archive

    $ArchiveLength = (Get-Item -LiteralPath $Archive).Length
    if ($ArchiveLength -eq 0 -or $ArchiveLength -gt $MaxArchiveBytes) {
        throw 'release archive size is outside the allowed range'
    }

    $ActualSha256 = (Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ActualSha256 -ne $ArchiveSha256) {
        throw 'release archive checksum mismatch'
    }

    Expand-Archive -LiteralPath $Archive -DestinationPath $Extracted
    $Binaries = @(Get-ChildItem -LiteralPath $Extracted -Filter 'membridge.exe' -File -Recurse)
    if ($Binaries.Count -ne 1) {
        throw "release archive contained $($Binaries.Count) membridge executables; expected exactly one"
    }

    New-Item -ItemType Directory -Path $InstallDirectory -Force | Out-Null
    [IO.File]::Copy($Binaries[0].FullName, $Staging, $true)
    Unblock-File -LiteralPath $Staging
    if (Test-Path -LiteralPath $Destination) {
        [IO.File]::Replace($Staging, $Destination, $null)
    } else {
        [IO.File]::Move($Staging, $Destination)
    }

    $InstalledVersion = & $Destination --version
    if ($LASTEXITCODE -ne 0 -or $InstalledVersion -ne "membridge $Version") {
        throw "installed binary did not report membridge $Version"
    }

    if (-not $NoModifyPath) {
        $UserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        $PathEntries = @($UserPath -split ';' | Where-Object { $_ -and $_ -ne $InstallDirectory })
        $UpdatedPath = (@($InstallDirectory) + $PathEntries) -join ';'
        [Environment]::SetEnvironmentVariable('Path', $UpdatedPath, 'User')

        $CurrentPathEntries = @($env:Path -split ';' | Where-Object { $_ -and $_ -ne $InstallDirectory })
        $env:Path = (@($InstallDirectory) + $CurrentPathEntries) -join ';'
    }

    Write-Output "installed membridge $Version at $Destination from a checksum-verified release archive"
} finally {
    [Net.ServicePointManager]::SecurityProtocol = $PreviousSecurityProtocol
    if (Test-Path -LiteralPath $Staging) {
        Remove-Item -LiteralPath $Staging -Force
    }
    if (Test-Path -LiteralPath $TemporaryDirectory) {
        Remove-Item -LiteralPath $TemporaryDirectory -Recurse -Force
    }
}
