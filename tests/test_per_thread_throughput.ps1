param(
    [string]$SourcePath = (Join-Path $PSScriptRoot '..\src\ntttcp.c')
)

$ErrorActionPreference = 'Stop'

function Assert-True {
    param(
        [bool]$Condition,
        [string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Get-FunctionBody {
    param(
        [string]$Source,
        [string]$StartMarker,
        [string]$EndMarker
    )

    $start = $Source.IndexOf($StartMarker, [StringComparison]::Ordinal)
    Assert-True ($start -ge 0) "Could not find function marker '$StartMarker'."

    $end = $Source.IndexOf($EndMarker, $start, [StringComparison]::Ordinal)
    Assert-True ($end -gt $start) "Could not find end marker '$EndMarker'."

    return $Source.Substring($start, $end - $start)
}

$source = Get-Content -LiteralPath $SourcePath -Raw
$functions = @(
    @{
        Name = 'synchronous worker'
        Body = Get-FunctionBody $source 'DoSendsReceives(' 'PostAsynchBuffer('
    },
    @{
        Name = 'asynchronous worker'
        Body = Get-FunctionBody $source 'DoAsynchSendsReceives(' 'AllocateAsynchBuffers('
    }
)

foreach ($function in $functions) {
    $body = $function.Body
    $name = $function.Name

    Assert-True (
        $body -notmatch '(?s)if\s*\(\s*tcp_row\s*\)\s*\{\s*if\s*\(\s*start_recording_results'
    ) "$name still gates worker timing on tcp_row."

    Assert-True (
        $body -match '(?s)if\s*\(\s*start_recording_results\s*&&\s*!time0_was_set\s*\)\s*\{.*?_ftime\(\&time0\);.*?if\s*\(\s*tcp_row\s*\)\s*\{\s*GetEstats\(tcp_row,\s*\&test_begin_estats\);.*?time0_was_set\s*=\s*TRUE;'
    ) "$name does not record the start time independently of EStats."

    Assert-True (
        $body -match '(?s)else\s+if\s*\(\s*time0_was_set\s*&&\s*!start_recording_results\s*&&\s*!time1_was_set\s*\)\s*\{\s*_ftime\(\&time1\);.*?if\s*\(\s*tcp_row\s*\)\s*\{\s*GetEstats\(tcp_row,\s*\&test_end_estats\);.*?time1_was_set\s*=\s*TRUE;'
    ) "$name does not record the end time independently of EStats."

    Assert-True ($body.Contains('if (flags.get_estats && tcp_row)')) "$name can mark unavailable EStats as available."
    Assert-True ($body.Contains('local_perf_info->bytes_transferred +=')) "$name no longer records per-thread bytes."
}

Write-Output 'Per-thread throughput regression checks passed.'
