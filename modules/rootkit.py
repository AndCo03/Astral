"""
Rootkit detection module for the Linux audit tool.
Runs chkrootkit and rkhunter.
"""

import re

NAME = "Rootkit Check"
PACKAGES = ["chkrootkit", "rkhunter"]


def _determine_severity(output):
    """
    Analyze the combined output of chkrootkit and rkhunter to decide severity.

    Notes:
    - chkrootkit prints "not infected" for clean checks and "INFECTED"
      (uppercase) only when something suspicious is found. A naive
      substring match on "infected" would flag every clean system.
    - rkhunter reports the number of suspected rootkits in the line
      "Possible rootkits: N" as part of its summary.
    - Informational warnings are common on a freshly installed system and
      should not be treated as High by default.
    """
    # 1. chkrootkit: search for "INFECTED" as a whole word
    infected_lines = [
        line.strip() for line in output.splitlines()
        if re.search(r'\bINFECTED\b', line)
    ]
    if infected_lines:
        return "Critical", "chkrootkit flagged: " + "; ".join(infected_lines[:5])

    # 2. rkhunter: search for the rootkit count in the summary
    m = re.search(r'Possible rootkits\s*:\s*(\d+)', output, re.IGNORECASE)
    if m and int(m.group(1)) > 0:
        return "Critical", f"rkhunter detected {m.group(1)} possible rootkit(s)."

    # 3. Informational warnings -> Low at most.
    if re.search(r'\[\s*Warning\s*\]', output) or 'Warning:' in output:
        return "Low", "Informational warnings present (typical of a clean system)."

    return "OK", "No rootkits detected."


def run(ssh, report, pkg_mgr):
    installed = pkg_mgr.install(PACKAGES)
    missing = [p for p in PACKAGES
               if p not in installed and not pkg_mgr.is_installed(p)]
    if len(missing) == len(PACKAGES):
        report.add_module(
            name=NAME,
            commands=[f"install {' '.join(PACKAGES)}"],
            output="",
            severity="Info",
            notes="Neither chkrootkit nor rkhunter could be installed."
        )
        return

    commands = []
    outputs = []

    if "chkrootkit" not in missing:
        cmd = "chkrootkit"
        commands.append(cmd)
        stdout, stderr, code = ssh.execute(cmd, sudo=True, timeout=600)
        outputs.append(f"$ {cmd}\n{stdout}")
        if stderr.strip():
            outputs.append(f"[stderr]\n{stderr}")
        if code != 0:
            outputs.append(f"[exit code: {code}]")

    if "rkhunter" not in missing:
        cmd_update = "rkhunter --update"
        commands.append(cmd_update)
        stdout, stderr, code = ssh.execute(cmd_update, sudo=True, timeout=300)
        outputs.append(f"$ {cmd_update}\n{stdout}")
        if stderr.strip():
            outputs.append(f"[stderr]\n{stderr}")
        if code != 0:
            outputs.append(f"[exit code: {code}]")

        cmd_check = "rkhunter --check --skip-keypress"
        commands.append(cmd_check)
        stdout, stderr, code = ssh.execute(cmd_check, sudo=True, timeout=900)
        outputs.append(f"$ {cmd_check}\n{stdout}")
        if stderr.strip():
            outputs.append(f"[stderr]\n{stderr}")
        if code != 0:
            outputs.append(f"[exit code: {code}]")

    full_output = "\n\n".join(outputs)
    severity, notes = _determine_severity(full_output)

    if missing:
        notes = (notes + " " if notes else "") + f"Missing packages: {', '.join(missing)}"

    report.add_module(
        name=NAME,
        commands=commands,
        output=full_output,
        severity=severity,
        notes=notes
    )