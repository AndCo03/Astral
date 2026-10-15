"""
Trivy module for the Linux audit tool.
Downloads the Trivy binary, scans the remote filesystem for vulnerabilities,
parses the JSON output, and removes the binary and cache afterwards.
"""

import json

NAME = "Trivy Filesystem Vulnerability Scan"

INSTALL_URL = "https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh"
TRIVY_BIN = "/usr/local/bin/trivy"

SKIP_DIRS = [
    "/proc", "/sys", "/dev", "/run",
    "/var/lib/docker", "/snap", "/var/lib/containerd"
]

MAX_VULNS_IN_OUTPUT = 50


def _trivy_installed(ssh):
    _, _, code = ssh.execute(f"command -v {TRIVY_BIN}", sudo=False, timeout=15)
    return code == 0


def _install_trivy(ssh):
    cmd = f"curl -sfL {INSTALL_URL} | sh -s -- -b /usr/local/bin"
    _, stderr, code = ssh.execute(cmd, sudo=True, timeout=180)
    return code == 0, stderr


def _cleanup_trivy(ssh, was_installed):
    if was_installed:
        return
    ssh.execute(f"rm -f {TRIVY_BIN}", sudo=True, timeout=15)
    ssh.execute("rm -rf /root/.cache/trivy", sudo=True, timeout=15)


def _parse_trivy_json(json_output):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    top = []
    try:
        data = json.loads(json_output)
    except json.JSONDecodeError:
        return counts, top

    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            sev = vuln.get("Severity", "UNKNOWN").upper()
            if sev in counts:
                counts[sev] += 1
            if sev in ("CRITICAL", "HIGH") and len(top) < MAX_VULNS_IN_OUTPUT:
                top.append({
                    "id": vuln.get("VulnerabilityID", "N/A"),
                    "pkg": vuln.get("PkgName", "N/A"),
                    "severity": sev,
                    "title": (vuln.get("Title") or "")[:120]
                })
    return counts, top


def _determine_severity(counts):
    total = sum(counts.values())
    if counts["CRITICAL"] > 0:
        return "Critical", (f"{counts['CRITICAL']} critical, "
                            f"{counts['HIGH']} high vulnerabilities.")
    if counts["HIGH"] > 0:
        return "High", f"{counts['HIGH']} high vulnerabilities."
    if counts["MEDIUM"] > 0:
        return "Medium", f"{counts['MEDIUM']} medium vulnerabilities."
    if counts["LOW"] > 0:
        return "Low", f"{counts['LOW']} low vulnerabilities."
    if total == 0:
        return "OK", "No vulnerabilities found in scanned packages."
    return "Low", f"{total} vulnerabilities found (low/unknown severity)."


def _determine_probability(counts):
    """
    Probability of exploitation based on the most severe findings.

    - Any CRITICAL -> Critical
    - Any HIGH     -> High
    - Any MEDIUM   -> Medium
    - Only LOW     -> Low
    - Nothing      -> Low
    """
    if counts["CRITICAL"] > 0:
        return "Critical"
    if counts["HIGH"] > 0:
        return "High"
    if counts["MEDIUM"] > 0:
        return "Medium"
    return "Low"


def _build_command():
    skip_args = " ".join(f"--skip-dirs {d}" for d in SKIP_DIRS)
    return (
        f"{TRIVY_BIN} fs --scanners vuln "
        f"--severity HIGH,CRITICAL "
        f"--format json "
        f"{skip_args} "
        f"/"
    )


def run(ssh, report, pkg_mgr):
    was_installed = _trivy_installed(ssh)

    if not was_installed:
        ok, err = _install_trivy(ssh)
        if not ok:
            report.add_module(
                name=NAME,
                commands=["install trivy via script"],
                output=f"[stderr]\n{err}",
                severity="N/D",
                notes="Could not install Trivy on the target."
            )
            return
    else:
        ssh.execute(f"{TRIVY_BIN} --download-db-only", sudo=True, timeout=300)

    command = _build_command()
    stdout, stderr, code = ssh.execute(command, sudo=True, timeout=900)

    output = stdout
    if stderr.strip():
        output += f"\n\n[stderr]\n{stderr}"

    counts, top_vulns = _parse_trivy_json(stdout)
    severity, notes = _determine_severity(counts)
    probability = _determine_probability(counts)

    if code != 0:
        notes = (notes + " " if notes else "") + f"trivy exited with code {code}."

    summary_lines = [
        "Trivy Vulnerability Summary:",
        f"  CRITICAL: {counts['CRITICAL']}",
        f"  HIGH:     {counts['HIGH']}",
        f"  MEDIUM:   {counts['MEDIUM']}",
        f"  LOW:      {counts['LOW']}",
        f"  UNKNOWN:  {counts['UNKNOWN']}",
    ]
    if top_vulns:
        summary_lines.append("\nTop vulnerabilities (CRITICAL/HIGH):")
        for v in top_vulns:
            summary_lines.append(
                f"  [{v['severity']}] {v['id']} in {v['pkg']} — {v['title']}"
            )

    display_output = "\n".join(summary_lines)
    if len(stdout) > 5000:
        display_output += f"\n\n[... JSON raw output truncated ({len(stdout)} bytes) ...]"

    report.add_module(
        name=NAME,
        commands=[command],
        output=display_output,
        severity=severity,
        notes=notes,
        probability=probability,
    )

    try:
        _cleanup_trivy(ssh, was_installed)
    except Exception:
        pass