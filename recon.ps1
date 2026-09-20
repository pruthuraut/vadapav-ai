param(
    [Parameter(Mandatory = $true)] [string] $Target,
    [string] $Agents = "all",
    [ValidateSet("json", "markdown", "md", "html")] [string] $Export = "json"
)

$ErrorActionPreference = "Stop"
python3 -m bb_harness --target $Target --mode host --run $Agents --export $Export
