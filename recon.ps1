param(
    [Parameter(Mandatory = $true)] [string] $Target,
    [ValidateSet("host", "container")] [string] $Mode = "container",
    [string] $Agents = "all",
    [ValidateSet("json", "markdown", "md", "html")] [string] $Export = "json"
)

$ErrorActionPreference = "Stop"
python -m bb_harness --target $Target --mode $Mode --run $Agents --export $Export
