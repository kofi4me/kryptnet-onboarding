#!/usr/bin/env bash
set -euo pipefail

echo "This script is intended for the scanner-worker image or an isolated Ubuntu scanner VM."
echo "It installs additional non-destructive assessment tools used by KryptScan."

apt-get update
apt-get install -y ca-certificates curl git unzip wget jq golang-go

export GOPATH="${GOPATH:-/opt/go}"
export PATH="${PATH}:${GOPATH}/bin"
mkdir -p "${GOPATH}/bin"

go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/owasp-amass/amass/v4/...@latest

curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/gitleaks/gitleaks/master/scripts/install.sh | sh -s -- -b /usr/local/bin

if [[ ! -d /opt/testssl.sh ]]; then
  git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh
fi
ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

echo "Extra scanner tools installed. Run tool health checks before production use."
