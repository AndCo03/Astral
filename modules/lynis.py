"""
Lynis module for the Linux audit tool.
Runs lynis audit system and returns its output.
"""

import re

NAME = "Lynis System Audit"
PACKAGE = "lynis"


def _parse_lynis(output):
    """Extract number of warnings and suggestions from Lynis output."""
    warnings = 0
    suggestions = 0
    w_match = re.search(r'Warnings\s*\((\d+)\)', output, re.IGNORECASE)
    if w_match:
        warnings = int(w_match.group(1))
    s_match = re.search(r'Suggestions\s*\((\d+)\)', output, re.IGNORECASE)
    if s_match:
        suggestions = int(s_match.group(1))
    return warnings, suggestions


def _determine_severity(warnings, suggestions):
    if warnings > 5:
        return "High", f"{warnings} warnings detected."
    if warnings > 0:
        return "Medium", f"{warnings} warnings detected."
    if suggestions > 0:
        return "Low", f"{suggestions} hardening suggestions."
    return "OK", "No critical warnings or suggestions."


def _determine_probability(warnings, suggestions):
    """
    Probability that an attacker can exploit the current misconfigurations.

    - Many warnings (> 5)   -> High
    - Few warnings (1-5)    -> Medium
    - Only suggestions      -> Low
    - Nothing               -> Low
    """
    if warnings > 5:
        return "High"
    if warnings > 0:
        return "Medium"
    if suggestions > 0:
        return "Low"
    return "Low"


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
    probability = _determine_probability(warnings, suggestions)

    if code != 0:
        notes = (notes + " " if notes else "") + f"lynis exited with code {code}"

    report.add_module(
        name=NAME,
        commands=[command],
        output=output,
        severity=severity,
        notes=notes,
        probability=probability,
    )