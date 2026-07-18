# KryptNet Hetzner / Proxmox Deployment

This deployment runs the public web apps and the protected scanner worker on an Ubuntu 24.04 VM.

## Services

- `kryptnet-web`: Flask app serving KryptScan and onboarding
- `scanner-worker`: protected FastAPI scanner API
- `postgres`: production database
- `redis`: job queue/cache foundation
- `nginx`: reverse proxy for public domains

## DNS

Point these records to the Ubuntu VM public IP:

```text
kryptscan.kryptnet.org   A   <server-ip>
onboarding.kryptnet.org  A   <server-ip>
scanner.kryptnet.org     A   <server-ip>
```

`scanner.kryptnet.org` should expose only `/health` publicly. Scanner job endpoints require `SCANNER_WORKER_TOKEN` and are intended for KryptScan only.

## First Server Setup

On the Ubuntu VM:

```bash
sudo bash deploy/hetzner/scripts/bootstrap_ubuntu_vm.sh
```

Clone the repo:

```bash
sudo mkdir -p /opt/kryptnet
sudo chown "$USER:$USER" /opt/kryptnet
cd /opt/kryptnet
git clone https://github.com/kofi4me/kryptnet-onboarding.git
cd kryptnet-onboarding/deploy/hetzner
```

Create environment:

```bash
cp .env.example .env
nano .env
```

Generate secrets:

```bash
openssl rand -hex 32
openssl rand -hex 48
```

Use one value for `APP_SECRET` and one value for `SCANNER_WORKER_TOKEN`.

Start services:

```bash
docker compose up -d --build
```

Check status:

```bash
docker compose ps
docker compose logs -f kryptnet-web
docker compose logs -f scanner-worker
```

## SSL

The default Nginx config is HTTP-only so the stack can boot before certificates exist.

After DNS points to the VM, issue a certificate that covers:

```text
kryptscan.kryptnet.org
onboarding.kryptnet.org
scanner.kryptnet.org
```

Then enable the HTTPS template:

```bash
cp nginx/kryptnet-ssl.template nginx/conf.d/kryptnet.conf
docker compose restart nginx
```

The HTTPS template expects certificates in:

```text
/etc/letsencrypt/live/kryptscan.kryptnet.org/
```

## Scanner Tools

The worker image includes common package-managed tools where available:

- Nmap
- Nikto
- WhatWeb
- wafw00f
- SSLyze
- Semgrep
- Checkov

Some tools are installed by the optional extra-tool script or custom image build:

- Nuclei
- httpx
- Naabu
- dnsx
- Katana
- Subfinder
- Amass
- Trivy
- Grype
- Gitleaks
- testssl.sh

For a full production image, run `deploy/hetzner/scripts/install_extra_scanner_tools.sh` inside an isolated scanner build environment and bake those binaries into the worker image.

## KryptScan Environment

The important production values are:

```text
SCANNER_BACKEND=worker
SCANNER_WORKER_URL=http://scanner-worker:9000
SCANNER_WORKER_TOKEN=<same-token-used-by-worker>
ALLOW_PRIVATE_NETWORK_TARGETS=false
```

Keep `ALLOW_PRIVATE_NETWORK_TARGETS=false` unless the VM is isolated and the client has explicitly authorized internal network testing.

## Safe Operation

- Keep scanner jobs authenticated.
- Start with one scan at a time.
- Keep private/reserved targets blocked by default.
- Add stronger queueing and per-client rate limits before heavy MSP use.
- Run Greenbone/OpenVAS separately later; it is resource-heavy.
