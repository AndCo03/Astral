"""
Rootkit detection module for the Linux audit tool.
Runs chkrootkit and rkhunter.
"""


NAME = "Rootkit Check"
PACKAGES = ["chkrootkit", "rkhunter"]


def run(ssh, report, pkg_mgr):
    """
    Run chkrootkit and rkhunter on the remote host.

    :param ssh: SSHSession instance.
    :param report: Report instance.
    :param pkg_mgr: Shared PackageManager instance.
    """
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

    report.add_module(
        name=NAME,
        commands=commands,
        output="\n\n".join(outputs),
        severity="Info",
        notes=f"Missing packages: {', '.join(missing)}" if missing else None
    )