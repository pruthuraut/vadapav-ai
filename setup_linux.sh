#!/usr/bin/env bash
set -Eeuo pipefail

# Host setup for bb-harness. Run on a supported Debian/Ubuntu Linux host.
# This installs tools and wordlists; it does not configure credentials.

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="${TOOLS_DIR:-${HOME}/security-tools}"
WORDLIST_DIR="${WORDLIST_DIR:-${HOME}/wordlists}"
GO_BIN="${GOBIN:-${HOME}/go/bin}"

sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
  build-essential ca-certificates curl wget git jq unzip zip \
  dnsutils whois nmap masscan openssl libpcap-dev \
  python3 python3-venv python3-pip pipx golang-go ruby ruby-dev cargo rustc

# Distribution-specific utilities are useful when available, but should not
# prevent the portable core toolchain from being installed.
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
  rpcbind whatweb unicornscan || echo "[!] Optional apt tools unavailable"

mkdir -p "${TOOLS_DIR}" "${WORDLIST_DIR}" "${GO_BIN}"
export PATH="${GO_BIN}:${HOME}/.local/bin:${PATH}"

go_install() {
  local package="$1"
  echo "[+] go install ${package}"
  GOBIN="${GO_BIN}" go install "${package}"
}

# ProjectDiscovery and URL-discovery binaries used by the recon agents.
go_install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go_install github.com/projectdiscovery/httpx/cmd/httpx@latest
go_install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go_install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go_install github.com/projectdiscovery/katana/cmd/katana@latest
go_install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go_install github.com/owasp-amass/amass/v4/cmd/amass@master
go_install github.com/tomnomnom/assetfinder@latest
go_install github.com/tomnomnom/waybackurls@latest
go_install github.com/lc/gau/v2/cmd/gau@latest
go_install github.com/hakluke/hakrawler@latest
go_install github.com/ffuf/ffuf/v2@latest
go_install github.com/OJ/gobuster/v3@latest

optional_go_install() {
  go_install "$1" || echo "[!] Optional tool unavailable: $1"
}
optional_go_install github.com/rverton/webanalyze/cmd/webanalyze@latest
optional_go_install github.com/praetorian-inc/fingerprintx/cmd/fingerprintx@latest

# massdns is built locally because it is not distributed as a stable Go binary.
MASSDNS_DIR="${TOOLS_DIR}/massdns"
if [[ ! -x "${GO_BIN}/massdns" ]]; then
  rm -rf "${MASSDNS_DIR}"
  git clone --depth 1 https://github.com/blechschmidt/massdns.git "${MASSDNS_DIR}"
  make -C "${MASSDNS_DIR}"
  install -m 0755 "${MASSDNS_DIR}/bin/massdns" "${GO_BIN}/massdns"
fi

# Python-based recon utilities.
python3 -m venv "${TOOLS_DIR}/venv"
"${TOOLS_DIR}/venv/bin/pip" install --upgrade pip
"${TOOLS_DIR}/venv/bin/pip" install -r "${PROJECT_DIR}/requirements.txt"
"${TOOLS_DIR}/venv/bin/pip" install dnsrecon dirsearch arjun wafw00f jsbeautifier sublist3r knockpy paramspider xnLinkFinder trufflehog

gem install wpscan --no-document || echo "[!] Optional tool unavailable: wpscan"
cargo install rustscan --locked || echo "[!] Optional tool unavailable: rustscan"
cargo install feroxbuster --locked || echo "[!] Optional tool unavailable: feroxbuster"

# Optional utilities used by the JS skill when available.
pipx ensurepath || true
pipx install waymore || true

if [[ ! -d "${TOOLS_DIR}/LinkFinder" ]]; then
  git clone --depth 1 https://github.com/GerbenJavado/LinkFinder.git "${TOOLS_DIR}/LinkFinder"
fi

# Wordlists and templates used by the safe discovery stages.
if [[ ! -d "${WORDLIST_DIR}/SecLists" ]]; then
  git clone --depth 1 https://github.com/danielmiessler/SecLists.git "${WORDLIST_DIR}/SecLists"
fi
if [[ ! -d "${WORDLIST_DIR}/nuclei-templates" ]]; then
  git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git "${WORDLIST_DIR}/nuclei-templates"
fi
if [[ ! -d "${WORDLIST_DIR}/assetnote-wordlists" ]]; then
  git clone --depth 1 https://github.com/assetnote/commonspeak2-wordlists.git "${WORDLIST_DIR}/assetnote-wordlists"
fi

"${GO_BIN}/nuclei" -update-templates -ud "${WORDLIST_DIR}/nuclei-templates" || true

cat <<EOF

[+] Host setup complete.
Add these lines to ~/.bashrc or ~/.zshrc:
  export PATH="${GO_BIN}:$PATH"
  export BB_WORDLIST_DIR="${WORDLIST_DIR}"
  export NUCLEI_TEMPLATES="${WORDLIST_DIR}/nuclei-templates"

Run:
  source "${TOOLS_DIR}/venv/bin/activate"
  python3 "${PROJECT_DIR}/recon.py" example.com
EOF
