param(
    [switch] $SkipSystemPackages,
    [string] $ToolsDir = "$env:USERPROFILE\security-tools",
    [string] $WordlistDir = "$env:USERPROFILE\wordlists"
)

$ErrorActionPreference = "Stop"
$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Install-WingetPackage {
    param([string] $Id)
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        throw "winget is required. Install App Installer from the Microsoft Store, then rerun this script."
    }
    Write-Host "[+] Installing or updating $Id"
    winget install --id $Id --exact --silent --accept-package-agreements --accept-source-agreements
}

function Get-PythonCommand {
    if (Get-Command py -ErrorAction SilentlyContinue) { return "py" }
    if (Get-Command python -ErrorAction SilentlyContinue) { return "python" }
    throw "Python 3 was not found. Install Python.Python.3 with winget and rerun."
}

if (-not $SkipSystemPackages) {
    Install-WingetPackage "Git.Git"
    Install-WingetPackage "Python.Python.3.12"
    Install-WingetPackage "GoLang.Go"
    Install-WingetPackage "Insecure.Nmap"
}

$python = Get-PythonCommand
New-Item -ItemType Directory -Force -Path $ToolsDir, $WordlistDir | Out-Null
$venv = Join-Path $ProjectDir ".venv"
if ($python -eq "py") { & $python -3 -m venv $venv } else { & $python -m venv $venv }
$venvPython = Join-Path $venv "Scripts\python.exe"
& $venvPython -m pip install --upgrade pip
& $venvPython -m pip install -r (Join-Path $ProjectDir "requirements.txt")
& $venvPython -m pip install dnsrecon dirsearch arjun wafw00f jsbeautifier sublist3r knockpy paramspider xnLinkFinder trufflehog

$goBin = Join-Path $env:USERPROFILE "go\bin"
$env:Path = "$goBin;$env:Path"
$goPackages = @(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "github.com/projectdiscovery/katana/cmd/katana@latest",
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "github.com/owasp-amass/amass/v4/cmd/amass@master",
    "github.com/tomnomnom/assetfinder@latest",
    "github.com/tomnomnom/waybackurls@latest",
    "github.com/lc/gau/v2/cmd/gau@latest",
    "github.com/hakluke/hakrawler@latest",
    "github.com/ffuf/ffuf/v2@latest",
    "github.com/OJ/gobuster/v3@latest",
    "github.com/rverton/webanalyze/cmd/webanalyze@latest",
    "github.com/praetorian-inc/fingerprintx/cmd/fingerprintx@latest"
)
foreach ($package in $goPackages) {
    Write-Host "[+] go install $package"
    go install $package
}

function Clone-DepthOne {
    param([string] $Url, [string] $Destination)
    if (-not (Test-Path $Destination)) {
        git clone --depth 1 $Url $Destination
    }
}

Clone-DepthOne "https://github.com/danielmiessler/SecLists.git" (Join-Path $WordlistDir "SecLists")
Clone-DepthOne "https://github.com/projectdiscovery/nuclei-templates.git" (Join-Path $WordlistDir "nuclei-templates")
Clone-DepthOne "https://github.com/assetnote/commonspeak2-wordlists.git" (Join-Path $WordlistDir "assetnote-wordlists")
Clone-DepthOne "https://github.com/GerbenJavado/LinkFinder.git" (Join-Path $ToolsDir "LinkFinder")

$nuclei = Join-Path $goBin "nuclei.exe"
if (Test-Path $nuclei) {
    & $nuclei -update-templates -ud (Join-Path $WordlistDir "nuclei-templates")
}

[Environment]::SetEnvironmentVariable("BB_WORDLIST_DIR", $WordlistDir, "User")
[Environment]::SetEnvironmentVariable("NUCLEI_TEMPLATES", (Join-Path $WordlistDir "nuclei-templates"), "User")

Write-Host ""
Write-Host "[+] Windows host setup complete."
Write-Host "Activate the environment: .\.venv\Scripts\Activate.ps1"
Write-Host "Run recon: python recon.py example.com"
Write-Host "Set API keys in the environment or an ignored .env file before scanning."
