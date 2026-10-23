#Requires -Version 5.1
# Regression tests for the diagnostic tool; synthetic detections are not A/B evidence.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('evtx-audit-' + [Guid]::NewGuid().ToString('N'))
$source = Join-Path $testRoot 'native'
$canonical = Join-Path $testRoot 'jsonl'
$comparison = Join-Path $testRoot 'comparison'
foreach ($path in @($source, $canonical, $comparison)) { $null = New-Item -ItemType Directory -Path $path }
$rule = '73be1519-4648-4ed7-b305-605504afc242'
$channel = 'Microsoft-Windows-PowerShell/Operational'
$stamp = '2024-01-01T00:00:00.1234567Z'
$tool = Join-Path $PSScriptRoot 'Compare-Hayabusa.ps1'

function Assert-Equal($Actual, $Expected, [string]$Message) {
    if ($Actual -ne $Expected) { throw "$Message`: expected $Expected, got $Actual" }
}
function New-Detection([int]$Id, [string]$File, [bool]$Json) {
    $root = $source
    if ($Json) { $root = $canonical; $File += '.jsonl' }
    return [pscustomobject]@{
        RuleID = $rule; RecordID = "$Id"; Timestamp = $stamp; Level = 'medium'
        Computer = 'HOST'; Channel = $channel; EventID = '4104'; EvtxFile = (Join-Path $root $File)
        Details = 'discarded'; ExtraFieldInfo = 'discarded'
    }
}
function New-Record([int]$Id, [int]$Level, [string]$Hash) {
    return @{
        Event = @{ System = @{EventRecordID = $Id; Level = 3} }
        RecordNumber = $Id; EventID = 4104; Channel = $channel; Level = $Level
        Hostname = 'HOST'; '@timestamp' = $stamp
        _teg = @{schema = 'evtx-teg/1.1.0'; event_uid = "test:$Id"; source = @{sha256 = $Hash}}
    }
}

try {
    foreach ($file in @('PowerShell.evtx', 'Empty.evtx', 'Missing.evtx', 'Invalid.evtx')) {
        Set-Content -LiteralPath (Join-Path $source $file) -Value 'synthetic source, not a real EVTX' -Encoding UTF8
    }
    $hash = (Get-FileHash -LiteralPath (Join-Path $source 'PowerShell.evtx')).Hash.ToLowerInvariant()
    $records = @((New-Record 1 3 $hash), (New-Record 2 4 $hash), (New-Record 5 3 $hash), (New-Record 9 3 ('f' * 64)))
    $records | ForEach-Object { ConvertTo-Json -InputObject $_ -Depth 10 -Compress } |
        Set-Content -LiteralPath (Join-Path $canonical 'PowerShell.evtx.jsonl') -Encoding UTF8
    [IO.File]::WriteAllBytes((Join-Path $canonical 'Empty.evtx.jsonl'), [byte[]]@())
    Set-Content -LiteralPath (Join-Path $canonical 'Invalid.evtx.jsonl') -Value '{invalid json' -Encoding UTF8
    @((New-Detection 1 'PowerShell.evtx' $false), (New-Detection 1 'PowerShell.evtx' $false),
        (New-Detection 2 'PowerShell.evtx' $false), (New-Detection 3 'PowerShell.evtx' $false),
        (New-Detection 5 'PowerShell.evtx' $false), (New-Detection 6 'Empty.evtx' $false),
        (New-Detection 7 'Missing.evtx' $false), (New-Detection 8 'Invalid.evtx' $false),
        (New-Detection 9 'PowerShell.evtx' $false)) |
        Export-Csv -LiteralPath (Join-Path $comparison 'evtx.csv') -NoTypeInformation -Encoding UTF8
    $equivalentTime = New-Detection 5 'PowerShell.evtx' $true
    $equivalentTime.Timestamp = '2024-01-01T01:00:00.1234567+01:00'
    @((New-Detection 1 'PowerShell.evtx' $true), (New-Detection 4 'PowerShell.evtx' $true), $equivalentTime) |
        Export-Csv -LiteralPath (Join-Path $comparison 'jsonl.csv') -NoTypeInformation -Encoding UTF8
    $result = (& $tool -ComparisonDirectory $comparison -EvtxRoot $source -JsonlRoot $canonical) | ConvertFrom-Json
    Assert-Equal $result.NativeDetections 9 'Native count'
    Assert-Equal $result.JsonlDetections 3 'JSON count'
    Assert-Equal $result.MissingDetections 7 'Multiset missing count'
    Assert-Equal $result.ExtraDetections 1 'Multiset extra count'
    Assert-Equal $result.Equivalent $false 'Mismatch must not pass'
    $presence = @(Import-Csv -LiteralPath (Join-Path $result.OutputDirectory 'presence.csv'))
    $byId = @{}
    foreach ($row in $presence) { $byId[$row.RecordID] = $row }
    Assert-Equal $byId['1'].Status 'record_present' 'Existing event'
    Assert-Equal $byId['1'].Matches '1' 'Matching aliases must not count the same record twice'
    Assert-Equal $byId['1'].KnownRuleFieldsMatch 'True' 'Intact rule fields'
    Assert-Equal $byId['1'].TimestampMatchesDetection 'True' 'Event timestamp'
    Assert-Equal $byId['2'].KnownRuleFieldsMatch 'False' 'Changed System.Level alias'
    Assert-Equal $byId['2'].StructuredLevel '3' 'Structured value retained'
    Assert-Equal $byId['3'].Status 'record_absent' 'Absent event'
    Assert-Equal $byId['6'].Status 'jsonl_file_empty' 'Empty export'
    Assert-Equal $byId['7'].Status 'jsonl_file_missing' 'Missing export'
    Assert-Equal $byId['8'].Status 'jsonl_invalid' 'Invalid JSON must not look absent'
    Assert-Equal $byId['9'].SourceHashMatches 'False' 'Stale source hash'
    Assert-Equal $byId['1'].SourceHashMatches 'True' 'Original source hash'
    Assert-Equal (Get-FileHash -LiteralPath (Join-Path $source 'PowerShell.evtx')).Hash.ToLowerInvariant() $hash 'Source unchanged'

    # Zero JSON detections must be diagnosed as failure, never certified as parity.
    $empty = Join-Path $testRoot 'zero'
    $null = New-Item -ItemType Directory -Path $empty
    Copy-Item -LiteralPath (Join-Path $comparison 'evtx.csv') -Destination (Join-Path $empty 'evtx.csv')
    [IO.File]::WriteAllBytes((Join-Path $empty 'jsonl.csv'), [byte[]]@())
    $zero = (& $tool -ComparisonDirectory $empty -EvtxRoot $source -JsonlRoot $canonical -Inspect 1) | ConvertFrom-Json
    Assert-Equal $zero.MissingDetections 9 'Zero detections missing count'
    Assert-Equal $zero.Equivalent $false 'Zero detections failure'
    Write-Host 'Hayabusa comparison regression checks passed.'
} finally {
    Remove-Item -LiteralPath $testRoot -Recurse -Force
}
