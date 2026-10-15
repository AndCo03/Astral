"""
ssh-audit module for the Linux audit tool.
Audits the SSH server configuration on the target for weak algorithms,
CVE exposure, and policy compliance.
"""

import json

NAME = "SSH Server Audit"
PACKAGE = "ssh-audit"


def _parse_ssh_audit_json(json_output):
    """
    Parses the JSON output of ssh-audit.
Returns (fail_count, warn_count, info_count, crit_algos, warn_algos).
    """
    try:
        data = json.loads(json_output)
    except json.JSONDecodeError:
        return 0, 0, 0, [], []

    fail_count = 0
    warn_count = 0
    info_count = 0
    crit_algos = []
    warn_algos = []

    # ssh-audit organize the output per categories: kex, key, enc, mac
    for category in ("kex", "key", "enc", "mac"):
        for item in data.get(category, []):
            alg = item.get("algorithm", "N/A")
            notes = item.get("notes", {})
            fails = notes.get("fail", [])
            warns = notes.get("warn", [])
            infos = notes.get("info", [])

            fail_count += len(fails)
            warn_count += len(warns)
            info_count += len(infos)

            if fails:
                crit_algos.append({
                    "category": category,
                    "algorithm": alg,
                    "reason": fails[0] if fails else ""
                })
            elif warns:
                warn_algos.append({
                    "category": category,
                    "algorithm": alg,
                    "reason": warns[0] if warns else ""
                })

    return fail_count, warn_count, info_count, crit_algos, warn_algos


def _determine_severity(fail_count, warn_count):
    """
    Severity based on the results of ssh-audit.
    - fail: critical algorithms (SHA-1, DH group1, etc.)
    - warn: weak algorithms but not critical (CBC, NIST keys, etc.)
    """
    if fail_count > 0:
        return "High", f"{fail_count} critical algorithm issue(s) detected."
    if warn_count > 0:
        return "Medium", f"{warn_count} weak algorithm(s) detected."
    return "OK", "No weak algorithms or critical issues detected."


def _build_summary(crit_algos, warn_algos, fail_count, warn_count):
    """Builds a readable summary for the raw output."""
    lines = []
    lines.append("SSH-Audit Summary:")
    lines.append(f"  Critical (fail): {fail_count}")
    lines.append(f"  Warnings (warn): {warn_count}")

    if crit_algos:
        lines.append("\nCritical algorithms:")
        for item in crit_algos[:10]:
            lines.append(
                f"  [{item['category']}] {item['algorithm']} — {item['reason']}"
            )

    if warn_algos:
        lines.append("\nWeak algorithms:")
        for item in warn_algos[:10]:
            lines.append(
                f"  [{item['category']}] {item['algorithm']} — {item['reason']}"
            )

    return "\n".join(lines)


def run(ssh, report, pkg_mgr):
    # ssh-audit is in the standard Debian/Ubuntu repositories (universe)
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

    # ssh-audit scans the SSH server listening on localhost:22
    command = f"ssh-audit -j localhost 2>/dev/null"
    stdout, stderr, code = ssh.execute(command, sudo=True, timeout=120)

    output = stdout
    if stderr.strip():
        output += f"\n\n[stderr]\n{stderr}"

    # ssh-audit: 0 = OK, 1 = FAIL (critical algorithms found)
    # Other codes indicate a connection or parsing error.
    if code == 1:
        report.add_module(
            name=NAME,
            commands=[command],
            output=output,
            severity="N/D",
            notes="ssh-audit could not connect to the SSH server."
        )
        return

    fail_count, warn_count, info_count, crit_algos, warn_algos = \
        _parse_ssh_audit_json(stdout)
    severity, notes = _determine_severity(fail_count, warn_count)

    # Add info about the number of algorithms analyzed
    notes = (notes + " " if notes else "") + \
        f"({info_count} informational notes, {len(crit_algos) + len(warn_algos)} algorithm issues)."

    # Build the readable summary and truncate the JSON output if it's too large
    summary = _build_summary(crit_algos, warn_algos, fail_count, warn_count)
    if len(stdout) > 3000:
        summary += f"\n\n[... JSON raw output truncated ({len(stdout)} bytes) ...]"

    report.add_module(
        name=NAME,
        commands=[command],
        output=summary,
        severity=severity,
        notes=notes
    )