"""
Lynis module for the Linux audit tool.
Runs lynis audit system and returns its output.
"""

import re

NAME = "Lynis System Audit"
PACKAGE = "lynis"

def _parse_lynis(output):
    """Estrae numero di warning e suggerimenti dall'output di Lynis."""
    warnings = 0
    suggestions = 0
    # Cerca pattern tipo "Warnings (3):" o "Suggestions (12):"
    w_match = re.search(r'Warnings\s*\((\d+)\)', output, re.IGNORECASE)
    if w_match:
        warnings = int(w_match.group(1))
    s_match = re.search(r'Suggestions\s*\((\d+)\)', output, re.IGNORECASE)
    if s_match:
        suggestions = int(s_match.group(1))
    return warnings, suggestions

def _determine_severity(warnings, suggestions):
    if warnings > 5:
        return "High", f"{warnings} warning detected."
    elif warnings > 0:
        return "Medium", f"{warnings} warning detected."
    elif suggestions > 0:
        return "Low", f"{suggestions} suggestions for hardening."
    else:
        return "OK", "No critical warnings or suggestions."

def run(ssh, report, pkg_mgr):
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

    command = "lynis audit system --quick --no-colors"
    stdout, stderr, code = ssh.execute(command, sudo=True, timeout=300)

    output = stdout
    if stderr.strip():
        output += "\n\n[stderr]\n" + stderr

    warnings, suggestions = _parse_lynis(stdout)
    severity, notes = _determine_severity(warnings, suggestions)

    if code != 0:
        notes = (notes + " " if notes else "") + f"lynis exited with code {code}"

    report.add_module(
        name=NAME,
        commands=[command],
        output=output,
        severity=severity,
        notes=notes
    )