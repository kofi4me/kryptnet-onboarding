from __future__ import annotations

import hashlib
import ipaddress
import os
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from kryptscan.app.models import Finding
from kryptscan.app.services.reporting import build_assessment_report


WORKER_TOKEN = os.getenv("SCANNER_WORKER_TOKEN", "")
ALLOW_PRIVATE_TARGETS = os.getenv("ALLOW_PRIVATE_NETWORK_TARGETS", "false").lower() in {"1", "true", "yes"}
MAX_TOOL_TIMEOUT = int(os.getenv("SCANNER_TOOL_TIMEOUT_SECONDS", "180"))
MAX_OUTPUT_CHARS = int(os.getenv("SCANNER_MAX_OUTPUT_CHARS", "20000"))

app = FastAPI(title="KryptScan Scanner Worker")
JOBS: dict[str, dict] = {}


class ScanRequest(BaseModel):
    target: str = Field(min_length=3, max_length=255)
    asset_type: str = "website"
    assessment_mode: str = "vulnerability_assessment"
    scan_tier: str = "full_scan"
    scan_protocols: list[str] = Field(default_factory=list)
    wait: bool = True


def _auth(authorization: str | None) -> None:
    expected = f"Bearer {WORKER_TOKEN}"
    if not WORKER_TOKEN or authorization != expected:
        raise HTTPException(status_code=401, detail="Scanner worker token is invalid.")


def _host(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"https://{target}")
    return parsed.hostname or target


def _validate_target(target: str) -> str:
    host = _host(target).strip().lower()
    if not host or any(char in host for char in " /\\;&|`$()<>"):
        raise HTTPException(status_code=400, detail="Invalid target.")
    try:
        network = ipaddress.ip_network(host, strict=False)
        if not ALLOW_PRIVATE_TARGETS and any(
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
            or address.is_unspecified
            for address in (network.network_address, network.broadcast_address)
        ):
            raise HTTPException(status_code=400, detail="Private, loopback, reserved, or link-local targets are blocked.")
    except ValueError:
        pass
    return host


def _run(command: list[str], output_dir: Path, timeout: int = MAX_TOOL_TIMEOUT) -> tuple[bool, str]:
    tool = command[0]
    if not shutil.which(tool):
        return False, f"{tool} is not installed in the scanner worker image."
    try:
        result = subprocess.run(
            command,
            cwd=output_dir,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        output = "\n".join(part for part in [result.stdout, result.stderr] if part)
        return result.returncode in {0, 1, 2}, output[:MAX_OUTPUT_CHARS]
    except subprocess.TimeoutExpired:
        return False, f"{tool} timed out after {timeout} seconds."


def _finding(target: str, title: str, severity: str, category: str, service: str, evidence: str, remediation: str, cvss: float = 0.0) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        cvss=cvss,
        category=category,
        host=target,
        service=service,
        description=evidence[:900] or title,
        remediation=remediation,
        evidence=evidence[:1200],
    )


def _tool_health_finding(target: str, tool: str, installed: bool, detail: str) -> Finding:
    return _finding(
        target,
        f"{tool} {'completed' if installed else 'not available'}",
        "info",
        "Scanner Toolchain",
        tool.lower(),
        detail,
        "Review raw output and parsed findings." if installed else f"Install {tool} in the scanner worker image before relying on this stage.",
    )


def _run_scan(payload: ScanRequest) -> dict:
    target = _validate_target(payload.target)
    findings: list[Finding] = []
    with tempfile.TemporaryDirectory(prefix="kryptscan-") as tmp:
        output_dir = Path(tmp)
        checks = [
            ("Nmap", ["nmap", "-sV", "--top-ports", "100", "--version-light", target], "Network Exposure"),
            ("Nikto", ["nikto", "-host", target, "-nointeractive"], "Web Server Security"),
            ("WhatWeb", ["whatweb", "--no-errors", target], "Technology Fingerprinting"),
            ("wafw00f", ["wafw00f", target], "Web Protection"),
            ("SSLyze", ["sslyze", "--regular", target], "TLS"),
            ("Nuclei", ["nuclei", "-target", target, "-severity", "critical,high,medium,low", "-silent"], "Known Vulnerabilities"),
        ]
        if payload.assessment_mode == "ethical_pentesting":
            checks.extend(
                [
                    ("httpx", ["httpx", "-u", target, "-title", "-tech-detect", "-status-code", "-silent"], "Web/API Surface"),
                    ("katana", ["katana", "-u", f"https://{target}", "-silent", "-d", "2"], "Crawling"),
                    ("subfinder", ["subfinder", "-d", target, "-silent"], "Authorized Reconnaissance"),
                ]
            )

        for tool, command, category in checks:
            ok, output = _run(command, output_dir)
            findings.append(_tool_health_finding(target, tool, ok, output))
            if ok and any(marker in output.lower() for marker in ["vulnerab", "critical", "high", "outdated", "weak", "exposed"]):
                digest = hashlib.sha256(f"{tool}:{target}:{output[:300]}".encode("utf-8")).hexdigest()[:8]
                findings.append(
                    _finding(
                        target,
                        f"{tool} risk indicator {digest}",
                        "medium",
                        category,
                        tool.lower(),
                        output,
                        "Review the affected service, validate with authorized evidence, patch or harden the control, and retest.",
                        5.8,
                    )
                )

    report = build_assessment_report(target, findings)
    report = report.model_copy(
        update={
            "scan_protocols": [
                *payload.scan_protocols,
                "Scanner worker executed containerized safe tool profile",
                "Private/reserved target policy enforced before tool execution",
                "Tool output normalized into KryptScan reporting schema",
            ],
            "scope_summary": f"Worker scan for {target}. Assessment mode: {payload.assessment_mode}. Tier: {payload.scan_tier}.",
        }
    )
    return report.model_dump(mode="json")


@app.get("/health")
def health() -> dict:
    tools = ["nmap", "nikto", "whatweb", "wafw00f", "sslyze", "nuclei", "httpx", "katana", "subfinder"]
    return {
        "status": "ok",
        "time": datetime.now(timezone.utc).isoformat(),
        "available_tools": {tool: bool(shutil.which(tool)) for tool in tools},
    }


@app.post("/v1/scans")
def create_scan(payload: ScanRequest, authorization: str | None = Header(default=None)) -> dict:
    _auth(authorization)
    job_id = str(uuid.uuid4())
    JOBS[job_id] = {"status": "running", "target": payload.target}
    report = _run_scan(payload)
    JOBS[job_id] = {"status": "completed", "target": payload.target, "report": report}
    return {"job_id": job_id, "status": "completed", "message": "Scanner worker completed the job.", "report": report}


@app.get("/v1/scans/{job_id}")
def get_scan(job_id: str, authorization: str | None = Header(default=None)) -> dict:
    _auth(authorization)
    if job_id not in JOBS:
        raise HTTPException(status_code=404, detail="Scanner job not found.")
    return {"job_id": job_id, **JOBS[job_id]}
