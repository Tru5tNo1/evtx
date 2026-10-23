#Requires -Version 5.1
<#
.SYNOPSIS
Compare existing verbose Hayabusa CSVs and inspect a few missing source records.
.DESCRIPTION
Read-only diagnostics: no detection scan, export conversion or source changes.
Run both Hayabusa paths with -b --iso-8601 -p verbose, and native input with -A -a.
Only detection identities are kept in memory; Details/ExtraFieldInfo are discarded.
The default rule uses Channel, EventID and System.Level, not ScriptBlockText.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ComparisonDirectory,
    [Parameter(Mandatory = $true)][string]$EvtxRoot,
    [Parameter(Mandatory = $true)][string]$JsonlRoot,
    [string]$RuleId = '73be1519-4648-4ed7-b305-605504afc242',
    [ValidateRange(1, 100)][int]$Inspect = 10
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$knownRule = '73be1519-4648-4ed7-b305-605504afc242'
$ordinal = [StringComparer]::Ordinal
$pathComparison = [StringComparison]::Ordinal
if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
    $pathComparison = [StringComparison]::OrdinalIgnoreCase
}
$ComparisonDirectory = [IO.Path]::GetFullPath($ComparisonDirectory)
$EvtxRoot = [IO.Path]::GetFullPath($EvtxRoot)
$JsonlRoot = [IO.Path]::GetFullPath($JsonlRoot)
$nativeCsv = Join-Path $ComparisonDirectory 'evtx.csv'
$jsonCsv = Join-Path $ComparisonDirectory 'jsonl.csv'
$entries = [Collections.Generic.Dictionary[string, object]]::new($ordinal)
$totals = [long[]]@(0, 0)
$required = @('RuleID', 'RecordID', 'Timestamp', 'Level', 'Computer', 'Channel', 'EventID', 'EvtxFile')

function Get-Field($Value, [string]$Name) {
    if ($null -ne $Value) {
        $property = $Value.PSObject.Properties[$Name]
        if ($null -ne $property) { return ,$property.Value }
    }
    return $null
}

function Get-Utc($Value) {
    # ConvertFrom-Json can materialize ISO strings as DateTime (depending on PS version).
    # Casting those back to string first would discard subsecond precision.
    if ($Value -is [DateTime]) { return [DateTimeOffset]::new($Value).ToUniversalTime().ToString('o') }
    if ($Value -is [DateTimeOffset]) { return $Value.ToUniversalTime().ToString('o') }
    return [DateTimeOffset]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture).ToUniversalTime().ToString('o')
}

function Get-RelativeSource([string]$Value, [string]$Root, [bool]$IsJson) {
    $prefix = $Root.TrimEnd([char[]]@('\', '/')) + [IO.Path]::DirectorySeparatorChar
    $full = [IO.Path]::GetFullPath($Value)
    if (-not $full.StartsWith($prefix, $pathComparison)) {
        throw "CSV source path is outside the supplied root: $Value"
    }
    $relative = $full.Substring($prefix.Length).Replace('\', '/')
    if ($IsJson) {
        if (-not $relative.EndsWith('.jsonl', [StringComparison]::OrdinalIgnoreCase)) {
            throw "Expected an .evtx.jsonl source path: $Value"
        }
        $relative = $relative.Substring(0, $relative.Length - 6)
    }
    return $relative
}

function Read-Detections([string]$Path, [string]$Root, [int]$Side) {
    $seen = 0
    Import-Csv -LiteralPath $Path -Encoding UTF8 | ForEach-Object {
        $row = $_
        if ($seen -eq 0) {
            foreach ($field in $required) {
                if ($null -eq $row.PSObject.Properties[$field]) {
                    throw "Missing $field in $Path; use -b --iso-8601 -p verbose."
                }
            }
        }
        $seen++
        if ($RuleId -and $row.RuleID -ne $RuleId) { return }
        $totals[$Side]++
        $relative = Get-RelativeSource $row.EvtxFile $Root ($Side -eq 1)
        $sourceKey = $relative
        if ($pathComparison -eq [StringComparison]::OrdinalIgnoreCase) { $sourceKey = $sourceKey.ToLowerInvariant() }
        $values = @($sourceKey, [string]$row.RuleID, [string]$row.RecordID,
            (Get-Utc $row.Timestamp), [string]$row.Level, [string]$row.Computer,
            [string]$row.Channel, [string]$row.EventID)
        $key = ConvertTo-Json -InputObject $values -Compress
        if (-not $entries.ContainsKey($key)) {
            $entries.Add($key, [pscustomobject]@{
                SourceRelativePath = $relative; RuleID = $row.RuleID; RecordID = $row.RecordID
                Timestamp = $row.Timestamp; Level = $row.Level; Computer = $row.Computer
                Channel = $row.Channel; EventID = $row.EventID; NativeCount = 0L; JsonlCount = 0L
            })
        }
        $entry = $entries[$key]
        if ($Side -eq 0) { $entry.NativeCount++ } else { $entry.JsonlCount++ }
    }
    if ($seen -eq 0 -and $Side -eq 0) { throw "No native detection rows in $Path; cannot establish a nonzero baseline." }
}

Read-Detections $nativeCsv $EvtxRoot 0
Read-Detections $jsonCsv $JsonlRoot 1
if ($totals[0] -eq 0) { throw 'The selected rule did not fire in the native baseline.' }
$missing = @($entries.Values | Where-Object { $_.NativeCount -gt $_.JsonlCount } |
    Sort-Object SourceRelativePath, RecordID, RuleID)
$extra = @($entries.Values | Where-Object { $_.JsonlCount -gt $_.NativeCount })
$missingCount = 0L
$extraCount = 0L
foreach ($entry in $missing) { $missingCount += $entry.NativeCount - $entry.JsonlCount }
foreach ($entry in $extra) { $extraCount += $entry.JsonlCount - $entry.NativeCount }

$output = Join-Path $ComparisonDirectory ('audit_' + (Get-Date -Format 'yyyyMMdd_HHmmss_fff'))
$null = New-Item -ItemType Directory -Path $output
$missing | Export-Csv -LiteralPath (Join-Path $output 'missing.csv') -NoTypeInformation -Encoding UTF8
$extra | Export-Csv -LiteralPath (Join-Path $output 'extra.csv') -NoTypeInformation -Encoding UTF8
$diagnostics = [Collections.Generic.List[object]]::new()
$hashes = [Collections.Generic.Dictionary[string, string]]::new($ordinal)

foreach ($group in ($missing | Select-Object -First $Inspect | Group-Object SourceRelativePath)) {
    $sourcePath = Join-Path $EvtxRoot $group.Name
    $jsonPath = Join-Path $JsonlRoot ($group.Name + '.jsonl')
    $wanted = [Collections.Generic.Dictionary[string, object]]::new($ordinal)
    foreach ($entry in $group.Group) {
        if ($wanted.ContainsKey([string]$entry.RecordID)) { continue }
        $diagnostic = [pscustomobject][ordered]@{
            SourceRelativePath = $group.Name; RecordID = $entry.RecordID; RuleID = $entry.RuleID
            Status = 'record_absent'; Matches = 0; RootRecordNumber = $null; StructuredRecordID = $null
            RootChannel = $null; RootEventID = $null
            RootLevel = $null; StructuredLevel = $null; RootComputer = $null
            RootTimestamp = $null; TimestampMatchesDetection = $null; KnownRuleFieldsMatch = $null
            Schema = $null; EventUid = $null; SourceHashMatches = $null
            OriginalReader = 'unavailable'; OriginalLevel = $null; OriginalChannel = $null; OriginalEventID = $null
        }
        $diagnostics.Add($diagnostic)
        $wanted.Add([string]$entry.RecordID, $diagnostic)
    }
    if (-not (Test-Path -LiteralPath $jsonPath -PathType Leaf)) {
        foreach ($item in $wanted.Values) { $item.Status = 'jsonl_file_missing' }
    } elseif ((Get-Item -LiteralPath $jsonPath).Length -eq 0) {
        foreach ($item in $wanted.Values) { $item.Status = 'jsonl_file_empty' }
    } else {
        $reader = [IO.StreamReader]::new($jsonPath, [Text.UTF8Encoding]::new($false, $true), $true)
        try {
            while ($null -ne ($line = $reader.ReadLine())) {
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                try { $record = ConvertFrom-Json -InputObject $line -ErrorAction Stop } catch {
                    foreach ($item in $wanted.Values) { $item.Status = 'jsonl_invalid' }
                    break
                }
                $system = Get-Field (Get-Field $record 'Event') 'System'
                $ids = @([string](Get-Field $record 'RecordNumber'), [string](Get-Field $system 'EventRecordID')) | Select-Object -Unique
                foreach ($id in $ids) {
                    if (-not $wanted.ContainsKey($id)) { continue }
                    $item = $wanted[$id]
                    $item.Matches++
                    if ($item.Matches -gt 1) { $item.Status = 'multiple_records'; continue }
                    $metadata = Get-Field $record '_teg'
                    $item.Status = 'record_present'
                    $item.RootRecordNumber = Get-Field $record 'RecordNumber'
                    $item.StructuredRecordID = Get-Field $system 'EventRecordID'
                    $item.RootChannel = Get-Field $record 'Channel'
                    $item.RootEventID = Get-Field $record 'EventID'
                    $item.RootLevel = Get-Field $record 'Level'
                    $item.StructuredLevel = Get-Field $system 'Level'
                    $item.RootComputer = Get-Field $record 'Hostname'
                    $item.RootTimestamp = Get-Field $record '@timestamp'
                    $item.Schema = Get-Field $metadata 'schema'
                    $item.EventUid = Get-Field $metadata 'event_uid'
                    $expected = $group.Group | Where-Object { [string]$_.RecordID -eq $id } | Select-Object -First 1
                    try {
                        $item.RootTimestamp = Get-Utc $item.RootTimestamp
                        $item.TimestampMatchesDetection = $item.RootTimestamp -eq (Get-Utc $expected.Timestamp)
                    } catch { $item.TimestampMatchesDetection = $false }
                    if ($item.RuleID -eq $knownRule) {
                        $item.KnownRuleFieldsMatch = ([string]$item.RootEventID -eq '4104' -and
                            [string]$item.RootLevel -eq '3' -and $item.RootChannel -cin @(
                                'Microsoft-Windows-PowerShell/Operational', 'PowerShellCore/Operational'))
                    }
                    if (Test-Path -LiteralPath $sourcePath -PathType Leaf) {
                        if (-not $hashes.ContainsKey($sourcePath)) {
                            $hashes.Add($sourcePath, (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToLowerInvariant())
                        }
                        $exportHash = Get-Field (Get-Field $metadata 'source') 'sha256'
                        $item.SourceHashMatches = $hashes[$sourcePath] -ceq [string]$exportHash
                    }
                }
            }
        } finally { $reader.Dispose() }
    }
    if (Get-Command Get-WinEvent -ErrorAction SilentlyContinue) {
        foreach ($item in $wanted.Values) {
            $item.OriginalReader = 'read_error'
            if ([string]$item.RecordID -notmatch '^[0-9]+$') { continue }
            try {
                $events = @(Get-WinEvent -Path $sourcePath -FilterXPath "*[System[EventRecordID=$($item.RecordID)]]" -Oldest -MaxEvents 2 -ErrorAction Stop)
                if ($events.Count -ne 1) { $item.OriginalReader = 'ambiguous'; continue }
                $item.OriginalReader = 'read'
                $item.OriginalLevel = $events[0].Level
                $item.OriginalChannel = $events[0].LogName
                $item.OriginalEventID = $events[0].Id
            } catch { }
        }
    }
}
$diagnostics | Export-Csv -LiteralPath (Join-Path $output 'presence.csv') -NoTypeInformation -Encoding UTF8
$summary = [ordered]@{
    NativeCsv = $nativeCsv; JsonlCsv = $jsonCsv; RuleID = $RuleId
    NativeDetections = $totals[0]; JsonlDetections = $totals[1]
    MissingDetections = $missingCount; ExtraDetections = $extraCount
    Equivalent = ($missingCount -eq 0 -and $extraCount -eq 0)
    InspectedEvents = $diagnostics.Count; OutputDirectory = $output
}
$summary | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $output 'summary.json') -Encoding UTF8
$summary | ConvertTo-Json
Write-Host 'Record presence and numeric System.Level are in presence.csv; CSV Level is rule severity.'
