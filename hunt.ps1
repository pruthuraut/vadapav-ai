param(
  [string]$Domain = "",
  [string]$Recon = "",
  [string]$Har = "",
  [string]$Output = ""
)
$argsList = @()
if ($Domain) { $argsList += @("--domain", $Domain) }
if ($Recon) { $argsList += @("--recon", $Recon) }
if ($Har) { $argsList += @("--har", $Har) }
if ($Output) { $argsList += @("--output", $Output) }
python3 run_hunt.py @argsList
