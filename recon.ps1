param(
    [Parameter(Mandatory = $true)] [string] $Target,
    [string] $Agents = "all",
    [ValidateSet("json", "markdown", "md", "html")] [string] $Export = "json"
)

$ErrorActionPreference = "Stop"
$python = if (Get-Command py -ErrorAction SilentlyContinue) { "py" } else { "python" }
if ($python -eq "py") {
    & $python -3 -m bb_harness --target $Target --mode host --run $Agents --export $Export
} else {
    & $python -m bb_harness --target $Target --mode host --run $Agents --export $Export
}
