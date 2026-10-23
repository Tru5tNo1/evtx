#Requires -Version 5.1
<#
.SYNOPSIS
List .evtx files with a missing EVTX signature, truncated file header, or read error.
.DESCRIPTION
Reads at most eight bytes per file. Does not repair, remove, rename or skip evidence
in the Rust export. A matching signature alone does not validate the whole file.
#>
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$Root)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$checked = 0
$invalid = 0
Get-ChildItem -LiteralPath $Root -Recurse -File -Force | Where-Object { $_.Extension -ieq '.evtx' } | ForEach-Object {
    $file = $_
    $checked++
    $stream = $null
    $read = 0
    $buffer = New-Object byte[] 8
    $issue = $null
    try {
        $stream = [IO.File]::Open($file.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read,
            ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        while ($read -lt 8) {
            $next = $stream.Read($buffer, $read, 8 - $read)
            if ($next -eq 0) { break }
            $read += $next
        }
        if ($stream.Length -lt 4096) {
            $issue = 'truncated_header'
        } elseif ([BitConverter]::ToString($buffer) -cne '45-6C-66-46-69-6C-65-00') {
            $issue = 'invalid_magic'
        }
    } catch {
        $issue = 'read_error'
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
    if ($null -ne $issue) {
        $invalid++
        [pscustomobject]@{
            Path = $file.FullName; Size = $file.Length; HeaderHex = [BitConverter]::ToString($buffer, 0, $read)
            Issue = $issue
        }
    }
}
Write-Host "Checked $checked EVTX files; $invalid require inspection. Signature checks do not validate event data."
