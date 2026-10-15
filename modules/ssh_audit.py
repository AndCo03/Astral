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
    Parsa l'output JSON di ssh-audit.
    Ritorna (fail_count, warn_count, info_count, crit_algos, warn_algos).
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

    # ssh-audit organizza l'output per categorie: kex, key, enc, mac
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
    Severity basata sui risultati di ssh-audit.
    - fail: algoritmi critici (SHA-1, DH group1, ecc.)
    - warn: algoritmi deboli ma non critici (CBC, chiavi NIST, ecc.)
    """
    if fail_count > 0:
        return "High", f"{fail_count} critical algorithm issue(s) detected."
    if warn_count > 0:
        return "Medium", f"{warn_count} weak algorithm(s) detected."
    return "OK", "No weak algorithms or critical issues detected."


def _build_summary(crit_algos, warn_algos, fail_count, warn_count):
    """Costruisce un riepilogo leggibile per il raw output."""
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
    # ssh-audit è nei repository standard Debian/Ubuntu (universe)
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

    # ssh-audit scansiona il server SSH in ascolto su localhost:22
    command = f"ssh-audit -j localhost 2>/dev/null"
    stdout, stderr, code = ssh.execute(command, sudo=True, timeout=120)

    output = stdout
    if stderr.strip():
        output += f"\n\n[stderr]\n{stderr}"

    # ssh-audit: 0 = OK, 1 = FAIL (algoritmi critici trovati)
    # Altri codici indicano un errore di connessione o parsing.
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

    # Aggiungi info sul numero di algoritmi analizzati
    notes = (notes + " " if notes else "") + \
        f"({info_count} informational notes, {len(crit_algos) + len(warn_algos)} algorithm issues)."

    # Costruisci il summary leggibile e, se l'output JSON è enorme, troncalo
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