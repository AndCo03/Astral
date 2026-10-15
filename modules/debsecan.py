"""
debsecan module for the Linux audit tool.
Checks installed packages against known Debian/Ubuntu vulnerabilities.
"""

import re

NAME = "debsecan Vulnerability Scan"
PACKAGE = "debsecan"

# Limit of lines displayed in the report (debsecan can produce hundreds of lines).
MAX_OUTPUT_LINES = 150


def _get_suite(ssh):
    """
    Retrieve the distribution codename (e.g., 'noble', 'bookworm').
    Try /etc/os-release first, then fall back to lsb_release.
    """
    stdout, _, code = ssh.execute(
        "grep -E '^VERSION_CODENAME=' /etc/os-release | cut -d= -f2 | tr -d '\"'",
        sudo=False, timeout=15
    )
    if code == 0 and stdout.strip():
        return stdout.strip()

    stdout, _, code = ssh.execute("lsb_release -cs", sudo=False, timeout=15)
    if code == 0 and stdout.strip():
        return stdout.strip()
    return None


def _parse_debsecan(output):
    """
    Parsing the default output of debsecan.
    Each line follows the format: CVE-YYYY-NNNN packagename [remote|local]
    Returns (set of unique CVEs, set of affected packages).
    """
    cves = set()
    packages = set()
    for line in output.splitlines():
        m = re.match(r'^(CVE-\d{4}-\d+)\s+(\S+)', line.strip())
        if m:
            cves.add(m.group(1))
            packages.add(m.group(2))
    return cves, packages


def _determine_severity(cve_count, package_count):
    """
    Determine severity based on the number of unique CVEs.
    Note: debsecan does not expose CVSS scores, so this is a rough proxy.
    """
    if cve_count == 0:
        return "OK", "No known vulnerabilities found."
    if cve_count <= 10:
        return "Low", f"{cve_count} CVE(s) in {package_count} package(s)."
    if cve_count <= 25:
        return "Medium", f"{cve_count} CVE(s) in {package_count} package(s)."
    if cve_count <= 50:
        return "High", f"{cve_count} CVE(s) in {package_count} package(s)."
    return "Critical", f"{cve_count} CVE(s) in {package_count} package(s)."


def run(ssh, report, pkg_mgr):
    # debsecan is reliable only on Debian.
    if pkg_mgr.distro_id != "debian":
        report.add_module(
            name=NAME,
            commands=[],
            output="",
            severity="N/D",
            notes=(f"debsecan is designed for Debian; "
                   f"on {pkg_mgr.distro_id} the Debian security tracker "
                   f"does not cover this distribution. Module skipped.")
        )
        return

    installed = pkg_mgr.install(PACKAGE)
    if PACKAGE not in installed and not pkg_mgr.is_installed(PACKAGE):
        report.add_module(
            name=NAME,
            commands=[f"install {PACKAGE}"],
            output="",
            severity="N/D",
            notes=f"Package {PACKAGE} could not be installed."
        )
        return

    suite = _get_suite(ssh)
    if not suite:
        report.add_module(
            name=NAME,
            commands=[],
            output="",
            severity="N/D",
            notes="Could not determine distribution codename."
        )
        return

    command = f"debsecan --suite {suite}"
    stdout, stderr, code = ssh.execute(command, sudo=True, timeout=300)

    output = stdout
    if stderr.strip():
        output += "\n\n[stderr]\n" + stderr

    # debsecan: 0 = no vulnerabilities found, 1 = vulnerabilities found.
    # Other codes indicate an error (network, unknown suite, etc.).
    if code not in (0, 1):
        report.add_module(
            name=NAME,
            commands=[command],
            output=output,
            severity="N/D",
            notes=f"debsecan exited with unexpected code {code}."
        )
        return

    cves, packages = _parse_debsecan(stdout)
    severity, notes = _determine_severity(len(cves), len(packages))

    # Truncate the output if it's too long, keeping stderr visible.
    lines = stdout.splitlines()
    if len(lines) > MAX_OUTPUT_LINES:
        output = "\n".join(lines[:MAX_OUTPUT_LINES])
        output += f"\n\n... [{len(lines) - MAX_OUTPUT_LINES} more lines truncated] ..."
        if stderr.strip():
            output += "\n\n[stderr]\n" + stderr

    report.add_module(
        name=NAME,
        commands=[command],
        output=output,
        severity=severity,
        notes=notes
    )