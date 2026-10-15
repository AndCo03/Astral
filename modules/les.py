"""
Linux Exploit Suggester (LES) module for the Linux audit tool.
Downloads LES on the target, runs it in "direct" mode with --checksec,
parses the output, then removes the script.
"""

import re

NAME = "Linux Exploit Suggester (LES)"

# URL raw official (mzet- / The-Z-Labs)
LES_URL = (
    "https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/"
    "master/linux-exploit-suggester.sh"
)
LES_PATH = "/tmp/les.sh"


def _download_les(ssh):
    """
    Download LES to /tmp using curl or wget.
    Returns True if the download is successful.
    """
    cmd = (
        f"curl -fsSL {LES_URL} -o {LES_PATH} || "
        f"wget -q {LES_URL} -O {LES_PATH}"
    )
    stdout, stderr, code = ssh.execute(cmd, sudo=False, timeout=60)
    if code != 0:
        return False

    ssh.execute(f"chmod +x {LES_PATH}", sudo=False, timeout=10)
    return True


def _cleanup_les(ssh):
    """Remove the LES script from the target (best effort)."""
    try:
        ssh.execute(f"rm -f {LES_PATH}", sudo=True, timeout=10)
    except Exception:
        pass


def _parse_les(output):
    """
    Extract unique CVEs from the LES output.
    LES prints lines of the type:
        Name: [CVE-2023-0386] ...
        CVE-2023-0386
    """
    cves = set()
    for line in output.splitlines():
        for m in re.finditer(r'CVE-\d{4}-\d{4,7}', line):
            cves.add(m.group(0))
    return cves


def _determine_severity(cve_count):
    """
    Determine severity based on the number of unique CVEs.
    Note: LES does not expose CVSS scores, so this is a rough proxy.
    """
    if cve_count == 0:
        return "OK", "No kernel privilege escalation exploits suggested."
    if cve_count <= 3:
        return "Low", f"{cve_count} CVE(s) suggested by LES."
    if cve_count <= 8:
        return "Medium", f"{cve_count} CVE(s) suggested by LES."
    if cve_count <= 15:
        return "High", f"{cve_count} CVE(s) suggested by LES."
    return "Critical", f"{cve_count} CVE(s) suggested by LES."


def run(ssh, report, pkg_mgr):
    # 1. Download to target
    if not _download_les(ssh):
        report.add_module(
            name=NAME,
            commands=[f"curl/wget {LES_URL}"],
            output="",
            severity="N/D",
            notes="Could not download LES on the target."
        )
        return

    try:
        # 2. Execution in "direct mode" + kernel hardening check
        command = f"bash {LES_PATH} --checksec"
        stdout, stderr, code = ssh.execute(command, sudo=True, timeout=180)

        output = stdout
        if stderr.strip():
            output += "\n\n[stderr]\n" + stderr

        # 3. Parsing
        cves = _parse_les(stdout)
        severity, notes = _determine_severity(len(cves))

        if code not in (0, 1):
            notes = (notes + " " if notes else "") + f"LES exited with code {code}."

        report.add_module(
            name=NAME,
            commands=[command],
            output=output,
            severity=severity,
            notes=notes
        )
    finally:
        # 4. Cleanup ALWAYS, even if the module crashes
        _cleanup_les(ssh)