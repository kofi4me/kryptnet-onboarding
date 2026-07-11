from __future__ import annotations

import hashlib

from kryptscan.app.models import Finding
from kryptscan.app.services.reporting import build_assessment_report, severity_from_cvss
from kryptscan.app.services.scanners.base import RefreshedScan, ScheduledScan


class MockScannerProvider:
    backend_name = "mock"

    _templates = [
        (
            "Outdated TLS configuration",
            8.7,
            "Transport Security",
            "https",
            "Enforce TLS 1.2+ only, disable weak ciphers, and rotate certificates where needed.",
        ),
        (
            "Administrative panel exposed to the internet",
            9.4,
            "Access Control",
            "https",
            "Restrict the management interface with VPN or IP allow-listing and require MFA.",
        ),
        (
            "Legacy SSH settings detected",
            6.8,
            "System Hardening",
            "ssh",
            "Disable password authentication, remove weak key exchange options, and rotate keys.",
        ),
        (
            "Known package vulnerability detected",
            7.9,
            "Patch Management",
            "https",
            "Update the affected package to the vendor-supported version and redeploy the service.",
        ),
        (
            "Missing security headers",
            5.6,
            "Web Application Security",
            "http",
            "Add HSTS, CSP, X-Content-Type-Options, and frame protections at the edge.",
        ),
        (
            "Information disclosure via service banner",
            3.7,
            "Information Exposure",
            "http",
            "Remove version banners and standardize error handling to limit recon data.",
        ),
        (
            "Weak web application control coverage",
            7.4,
            "OWASP Web Risk",
            "https",
            "Review authentication, authorization, input validation, and session controls against OWASP ASVS requirements.",
        ),
        (
            "API authorization validation required",
            8.2,
            "API Security",
            "https",
            "Validate object-level authorization, rate limits, token expiry, and sensitive endpoint access control.",
        ),
        (
            "Cloud exposure review required",
            6.9,
            "Cloud Security",
            "cloud",
            "Review public storage, security groups, IAM privilege scope, and logging coverage for the scoped environment.",
        ),
        (
            "Potential secrets exposure indicator",
            7.6,
            "Secrets Management",
            "https",
            "Rotate exposed credentials where confirmed and add automated secret scanning to the deployment pipeline.",
        ),
        (
            "Identity and MFA coverage gap",
            8.5,
            "Identity Security",
            "identity",
            "Enforce MFA, conditional access, least privilege, and privileged access review for administrator accounts.",
        ),
        (
            "Database network exposure requires review",
            8.1,
            "Database Security",
            "database",
            "Restrict database access to trusted application networks and require encrypted authenticated connections.",
        ),
        (
            "Endpoint detection coverage not validated",
            5.8,
            "Detection Engineering",
            "edr",
            "Confirm endpoint telemetry, alert routing, and incident response ownership for affected assets.",
        ),
        (
            "Backup and recovery control requires evidence",
            5.4,
            "Resilience",
            "backup",
            "Verify immutable backups, restoration testing, and recovery objectives for business-critical systems.",
        ),
    ]

    def schedule(self, target: str, asset_type: str) -> ScheduledScan:
        findings = self._build_findings(target, asset_type)
        report = build_assessment_report(target, findings)
        return ScheduledScan(
            status="completed",
            backend=self.backend_name,
            message="Mock scan completed successfully.",
            report=report,
        )

    def refresh(self, target: str, asset_type: str) -> RefreshedScan:
        findings = self._build_findings(target, asset_type)
        report = build_assessment_report(target, findings)
        return RefreshedScan(
            status="completed",
            message="Mock scan report refreshed.",
            report=report,
        )

    def _build_findings(self, target: str, asset_type: str) -> list[Finding]:
        fingerprint = hashlib.sha256(f"{target}:{asset_type}".encode("utf-8")).digest()
        total = 9 + (fingerprint[0] % 5)
        findings: list[Finding] = []

        for index in range(total):
            template = self._templates[index % len(self._templates)]
            title, base_cvss, category, service, remediation = template
            modifier = (fingerprint[index] % 12) / 10
            cvss = min(9.9, round(base_cvss + modifier, 1))
            severity = severity_from_cvss(cvss)
            port = {
                "http": "80/tcp",
                "https": "443/tcp",
                "ssh": "22/tcp",
                "cloud": "cloud",
                "identity": "iam",
                "database": "5432/tcp",
                "edr": "agent",
                "backup": "control",
            }.get(service, "0/tcp")
            findings.append(
                Finding(
                    title=title,
                    severity=severity,
                    cvss=cvss,
                    category=category,
                    host=target,
                    port=port,
                    service=service,
                    cve=f"CVE-2025-{1000 + fingerprint[index]}",
                    description=(
                        f"{title} was identified during the {asset_type} assessment for {target}. "
                        "The finding is normalized from the KryptScan professional test workflow and is prioritized "
                        "using severity, reachable exposure, control impact, and remediation urgency."
                    ),
                    remediation=remediation,
                    evidence=(
                        f"Test-mode evidence package: {service} checks, configuration review, known-risk correlation, "
                        f"and analyst-style triage were applied to {target}. Production deployments should connect "
                        "the installed scanner workers for raw Nmap, OWASP ZAP, Nikto, TLS, cloud, and AI triage artifacts."
                    ),
                )
            )

        return findings

