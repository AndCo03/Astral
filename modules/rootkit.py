"""
Rootkit detection module for the Linux audit tool.
Runs chkrootkit and rkhunter.
"""

NAME = "Rootkit Check"
PACKAGES = ["chkrootkit", "rkhunter"]

def _determine_severity(output):
    """Analizza l'output combinato per decidere la severity."""
    lowered = output.lower()
    if "infected" in lowered:
        return "Critical", "Possibile infezione rootkit rilevata (INFECTED)."
    if "warning" in lowered:
        return "High", "Warning rilevati durante il controllo rootkit."
    return "N/D", "Nessun rootkit o warning rilevante."

def run(ssh, report, pkg_mgr):
    installed = pkg_mgr.install(PACKAGES)
    missing = [p for p in PACKAGES
               if p not in installed and not pkg_mgr.is_installed(p)]
    if len(missing) == len(PACKAGES):
        report.add_module(
            name=NAME,
            commands=[f"install {' '.join(PACKAGES)}"],
            output="",
            severity="N/D",
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