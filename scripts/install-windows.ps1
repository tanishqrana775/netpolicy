<#
.SYNOPSIS
Installs or uninstalls a user-level Windows shim for the netpolicy CLI.

.DESCRIPTION
Configures a lightweight shim directory in %LOCALAPPDATA%\netpolicy\bin containing
netpolicy.cmd pointing to the project virtual environment (<repo>\.venv\Scripts\netpolicy.exe).
Adds this shim directory to the current user's PATH environment variable (HKCU\Environment)
without requiring Administrator privileges or modifying the system PATH.
Avoids adding the venv Scripts directory directly to PATH by default to prevent shadowing global python and pip.

.PARAMETER VenvPath
Path to the virtual environment directory. Defaults to <repo>\.venv.

.PARAMETER ShimDir
Path to the shim directory where netpolicy.cmd will be written. Defaults to %LOCALAPPDATA%\netpolicy\bin.

.PARAMETER Uninstall
Removes the shim directory from the user PATH, deletes netpolicy.cmd, and preserves PATH backups.

.PARAMETER AddVenvScriptsToPath
Opt-in switch to add <repo>\.venv\Scripts directly to user PATH. Warning: shadows global python and pip.

.EXAMPLE
.\scripts\install-windows.ps1
Installs netpolicy.cmd shim and adds %LOCALAPPDATA%\netpolicy\bin to user PATH.

.EXAMPLE
.\scripts\install-windows.ps1 -WhatIf
Previews the installation operations without modifying any files or registry values.

.EXAMPLE
.\scripts\install-windows.ps1 -Uninstall
Removes the shim and cleans user PATH.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$VenvPath = "",
    [string]$ShimDir = "$env:LOCALAPPDATA\netpolicy\bin",
    [switch]$Uninstall,
    [switch]$AddVenvScriptsToPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-ShimContent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExePath
    )
    return "@echo off`r`n`"$ExePath`" %*`r`nexit /b %ERRORLEVEL%`r`n"
}

function Get-UserPathRaw {
    [CmdletBinding()]
    param()
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $false)
    if ($null -eq $key) {
        return ""
    }
    try {
        $val = $key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if ($null -eq $val) {
            return ""
        }
        return [string]$val
    } finally {
        $key.Close()
    }
}

function Set-UserPathRaw {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$NewPath
    )
    if ($PSCmdlet.ShouldProcess("HKCU\Environment\Path", "Update user PATH")) {
        $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
        if ($null -eq $key) {
            $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
        }
        try {
            $key.SetValue('Path', $NewPath, [Microsoft.Win32.RegistryValueKind]::ExpandString)
            return $true
        } finally {
            $key.Close()
        }
    }
    return $false
}

function Test-PathEntryExists {
    [CmdletBinding()]
    param(
        [string]$RawPath,
        [string]$TargetDir
    )
    if ([string]::IsNullOrEmpty($RawPath) -or [string]::IsNullOrEmpty($TargetDir)) {
        return $false
    }
    $targetExpanded = [System.Environment]::ExpandEnvironmentVariables($TargetDir)
    $targetNormalized = try {
        [System.IO.Path]::GetFullPath($targetExpanded).TrimEnd('\', '/')
    } catch {
        $targetExpanded.TrimEnd('\', '/')
    }
    $entries = $RawPath.Split(';')
    foreach ($entry in $entries) {
        $trimmed = $entry.Trim()
        if ([string]::IsNullOrEmpty($trimmed)) {
            continue
        }
        $expanded = [System.Environment]::ExpandEnvironmentVariables($trimmed)
        $normalized = try {
            [System.IO.Path]::GetFullPath($expanded).TrimEnd('\', '/')
        } catch {
            $expanded.TrimEnd('\', '/')
        }
        if ([string]::Equals($normalized, $targetNormalized, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Add-PathEntry {
    [CmdletBinding()]
    param(
        [string]$RawPath,
        [Parameter(Mandatory = $true)]
        [string]$TargetDir
    )
    if (Test-PathEntryExists -RawPath $RawPath -TargetDir $TargetDir) {
        return $RawPath
    }
    $list = New-Object System.Collections.Generic.List[string]
    if (-not [string]::IsNullOrEmpty($RawPath)) {
        $entries = $RawPath.Split(';')
        foreach ($entry in $entries) {
            $trimmed = $entry.Trim()
            if (-not [string]::IsNullOrEmpty($trimmed)) {
                $list.Add($trimmed)
            }
        }
    }
    $list.Add($TargetDir)
    return [string]::Join(';', $list)
}

function Remove-PathEntry {
    [CmdletBinding()]
    param(
        [string]$RawPath,
        [Parameter(Mandatory = $true)]
        [string]$TargetDir
    )
    if ([string]::IsNullOrEmpty($RawPath)) {
        return ""
    }
    $targetExpanded = [System.Environment]::ExpandEnvironmentVariables($TargetDir)
    $targetNormalized = try {
        [System.IO.Path]::GetFullPath($targetExpanded).TrimEnd('\', '/')
    } catch {
        $targetExpanded.TrimEnd('\', '/')
    }
    $list = New-Object System.Collections.Generic.List[string]
    $entries = $RawPath.Split(';')
    foreach ($entry in $entries) {
        $trimmed = $entry.Trim()
        if ([string]::IsNullOrEmpty($trimmed)) {
            continue
        }
        $expanded = [System.Environment]::ExpandEnvironmentVariables($trimmed)
        $normalized = try {
            [System.IO.Path]::GetFullPath($expanded).TrimEnd('\', '/')
        } catch {
            $expanded.TrimEnd('\', '/')
        }
        if (-not [string]::Equals($normalized, $targetNormalized, [System.StringComparison]::OrdinalIgnoreCase)) {
            $list.Add($trimmed)
        }
    }
    return [string]::Join(';', $list)
}

function Save-PathBackup {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$RawPath
    )
    $backupDir = Join-Path -Path $env:LOCALAPPDATA -ChildPath "netpolicy"
    if (-not (Test-Path -LiteralPath $backupDir -PathType Container)) {
        if ($PSCmdlet.ShouldProcess($backupDir, "Create backup directory")) {
            $null = [System.IO.Directory]::CreateDirectory($backupDir)
        }
    }
    $timestamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
    $backupFile = Join-Path -Path $backupDir -ChildPath "path-backup-$timestamp.txt"
    if ($PSCmdlet.ShouldProcess($backupFile, "Save user PATH backup")) {
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($backupFile, $RawPath, $utf8NoBom)
        Write-Host "[OK] Backed up current user PATH to: $backupFile" -ForegroundColor Green
        return $backupFile
    }
    return $null
}

function Broadcast-EnvironmentChange {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    if ($PSCmdlet.ShouldProcess("Windows Environment", "Broadcast WM_SETTINGCHANGE notification")) {
        $code = @'
using System;
using System.Runtime.InteropServices;

public static class NetPolicyWin32 {
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern IntPtr SendMessageTimeout(
        IntPtr hWnd,
        uint Msg,
        UIntPtr wParam,
        string lParam,
        uint fuFlags,
        uint uTimeout,
        out UIntPtr lpdwResult
    );
}
'@
        if (-not ([System.Management.Automation.PSTypeName]'NetPolicyWin32').Type) {
            Add-Type -TypeDefinition $code
        }
        $HWND_BROADCAST = [IntPtr]0xffff
        $WM_SETTINGCHANGE = [uint32]0x001a
        $SMTO_ABORTIFHUNG = [uint32]0x0002
        $timeout = [uint32]5000
        $result = [UIntPtr]::Zero
        [NetPolicyWin32]::SendMessageTimeout(
            $HWND_BROADCAST,
            $WM_SETTINGCHANGE,
            [UIntPtr]::Zero,
            "Environment",
            $SMTO_ABORTIFHUNG,
            $timeout,
            [ref]$result
        ) | Out-Null
        Write-Host "[OK] Broadcasted environment change notification." -ForegroundColor Green
        return $true
    }
    return $false
}

function Invoke-Installer {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptRoot,
        [string]$VenvPath = "",
        [string]$ShimDir = "$env:LOCALAPPDATA\netpolicy\bin",
        [switch]$Uninstall,
        [switch]$AddVenvScriptsToPath
    )

    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "=== netpolicy Windows installer      ===" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    $repoRoot = [System.IO.Path]::GetFullPath((Join-Path -Path $ScriptRoot -ChildPath ".."))
    $resolvedVenv = if (-not [string]::IsNullOrEmpty($VenvPath)) {
        [System.IO.Path]::GetFullPath($VenvPath)
    } else {
        [System.IO.Path]::GetFullPath((Join-Path -Path $repoRoot -ChildPath ".venv"))
    }

    $venvScriptsDir = [System.IO.Path]::GetFullPath((Join-Path -Path $resolvedVenv -ChildPath "Scripts"))
    $netpolicyExe = [System.IO.Path]::GetFullPath((Join-Path -Path $venvScriptsDir -ChildPath "netpolicy.exe"))

    $expandedShimDir = [System.Environment]::ExpandEnvironmentVariables($ShimDir)
    $resolvedShimDir = [System.IO.Path]::GetFullPath($expandedShimDir)
    $shimPath = [System.IO.Path]::GetFullPath((Join-Path -Path $resolvedShimDir -ChildPath "netpolicy.cmd"))

    $currentRawPath = Get-UserPathRaw
    $isShimOnPath = Test-PathEntryExists -RawPath $currentRawPath -TargetDir $resolvedShimDir
    $pathStatus = if ($isShimOnPath) { "configured" } else { "not configured" }

    Write-Host "  Repo Root:        $repoRoot" -ForegroundColor DarkGray
    Write-Host "  Venv Scripts Dir: $venvScriptsDir" -ForegroundColor DarkGray
    Write-Host "  Shim Path:        $shimPath" -ForegroundColor DarkGray
    Write-Host "  User PATH Status: $pathStatus" -ForegroundColor DarkGray

    if ($Uninstall) {
        $needRemoveShim = Test-PathEntryExists -RawPath $currentRawPath -TargetDir $resolvedShimDir
        $needRemoveScripts = Test-PathEntryExists -RawPath $currentRawPath -TargetDir $venvScriptsDir

        if ($needRemoveShim -or $needRemoveScripts) {
            $null = Save-PathBackup -RawPath $currentRawPath
            $newPath = $currentRawPath
            if ($needRemoveShim) {
                $newPath = Remove-PathEntry -RawPath $newPath -TargetDir $resolvedShimDir
            }
            if ($needRemoveScripts) {
                $newPath = Remove-PathEntry -RawPath $newPath -TargetDir $venvScriptsDir
            }
            $didSet = Set-UserPathRaw -NewPath $newPath
            if ($didSet) {
                Write-Host "[OK] Removed netpolicy directory entries from user PATH." -ForegroundColor Green
            }
            $null = Broadcast-EnvironmentChange
        } else {
            Write-Host "[OK] netpolicy directories were not present in user PATH." -ForegroundColor Green
        }

        if (Test-Path -LiteralPath $shimPath -PathType Leaf) {
            if ($PSCmdlet.ShouldProcess($shimPath, "Delete shim file")) {
                Remove-Item -LiteralPath $shimPath -Force
                Write-Host "[OK] Deleted shim file: $shimPath" -ForegroundColor Green
            }
        } else {
            Write-Host "[OK] Shim file does not exist: $shimPath" -ForegroundColor Green
        }

        Write-Host "[OK] Uninstall complete. Backups preserved in: $env:LOCALAPPDATA\netpolicy" -ForegroundColor Green
        return 0
    }

    if (-not (Test-Path -LiteralPath $netpolicyExe -PathType Leaf)) {
        Write-Host "[ERR] Virtual environment executable not found: $netpolicyExe" -ForegroundColor Red
        Write-Host "      Please create the virtual environment and install netpolicy in editable mode:" -ForegroundColor Red
        Write-Host "        python -m venv .venv" -ForegroundColor Red
        Write-Host "        .\.venv\Scripts\python.exe -m pip install -e ." -ForegroundColor Red
        return 1
    }

    if (-not (Test-Path -LiteralPath $resolvedShimDir -PathType Container)) {
        if ($PSCmdlet.ShouldProcess($resolvedShimDir, "Create shim directory")) {
            $null = [System.IO.Directory]::CreateDirectory($resolvedShimDir)
        }
    }

    $shimContent = Get-ShimContent -ExePath $netpolicyExe
    if ($PSCmdlet.ShouldProcess($shimPath, "Write netpolicy.cmd shim")) {
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($shimPath, $shimContent, $utf8NoBom)
        Write-Host "[OK] Created/updated shim: $shimPath" -ForegroundColor Green
    }

    $needAddShim = -not (Test-PathEntryExists -RawPath $currentRawPath -TargetDir $resolvedShimDir)
    $needAddScripts = $AddVenvScriptsToPath -and (-not (Test-PathEntryExists -RawPath $currentRawPath -TargetDir $venvScriptsDir))

    if ($needAddShim -or $needAddScripts) {
        $null = Save-PathBackup -RawPath $currentRawPath
        $newPath = $currentRawPath
        if ($needAddShim) {
            $newPath = Add-PathEntry -RawPath $newPath -TargetDir $resolvedShimDir
        }
        if ($needAddScripts) {
            $newPath = Add-PathEntry -RawPath $newPath -TargetDir $venvScriptsDir
        }
        $didSet = Set-UserPathRaw -NewPath $newPath
        if ($didSet) {
            Write-Host "[OK] Added '$resolvedShimDir' to user PATH." -ForegroundColor Green
            if ($env:Path -notlike "*$resolvedShimDir*") {
                $env:Path = "$env:Path;$resolvedShimDir"
                Write-Host "[OK] Appended shim directory to current session PATH." -ForegroundColor Green
            }
        }

        $null = Broadcast-EnvironmentChange

        if ($needAddScripts -and $didSet) {
            Write-Host "[!!] WARNING: Added '$venvScriptsDir' directly to PATH. This shadows global python.exe and pip.exe." -ForegroundColor Yellow
        }
    } else {
        Write-Host "[OK] Shim directory is already configured in user PATH." -ForegroundColor Green
        if ($AddVenvScriptsToPath) {
            Write-Host "[OK] Venv Scripts directory is already configured in user PATH." -ForegroundColor Green
        }
    }

    Write-Host "[!!] Close and reopen CMD or PowerShell for the global 'netpolicy' command to take effect in new windows." -ForegroundColor Yellow
    Write-Host "[OK] Quick test: netpolicy --version" -ForegroundColor Green

    $resolved = Get-Command netpolicy -ErrorAction SilentlyContinue
    if ($null -ne $resolved) {
        $resolvedSource = if ($resolved.Source) { $resolved.Source } else { $resolved.Path }
        try {
            $fullResolved = [System.IO.Path]::GetFullPath($resolvedSource).TrimEnd('\', '/')
            $fullShim = [System.IO.Path]::GetFullPath($shimPath).TrimEnd('\', '/')
            if (-not [string]::Equals($fullResolved, $fullShim, [System.StringComparison]::OrdinalIgnoreCase)) {
                Write-Host "[!!] WARNING: 'netpolicy' currently resolves to '$resolvedSource' instead of '$shimPath'." -ForegroundColor Yellow
            }
        } catch {
            # Ignore path resolution error
        }
    }

    return 0
}

# Entry point: only invoke main when script is executed directly, not when dot-sourced
$isDotSourced = ($MyInvocation.InvocationName -eq '.') -or ($MyInvocation.Line -match '^\s*\.\s+')

if (-not $isDotSourced) {
    try {
        $exitCode = Invoke-Installer `
            -ScriptRoot $PSScriptRoot `
            -VenvPath $VenvPath `
            -ShimDir $ShimDir `
            -Uninstall:$Uninstall `
            -AddVenvScriptsToPath:$AddVenvScriptsToPath
        exit $exitCode
    } catch {
        Write-Host "[ERR] Unexpected installer error: $_" -ForegroundColor Red
        Write-Host $_.ScriptStackTrace -ForegroundColor Red
        exit 1
    }
}
