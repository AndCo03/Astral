"""
Lynis module for the Linux audit tool.
Runs lynis audit system and returns its output.
"""


NAME = "Lynis System Audit"
PACKAGE = "lynis"


def run(ssh, report, pkg_mgr):
    """
    Run the Lynis system audit on the remote host.

    :param ssh: SSHSession instance.
    :param report: Report instance.
    :param pkg_mgr: Shared PackageManager instance.
    """
    installed = pkg_mgr.install(PACKAGE)
    if PACKAGE not in installed and not pkg_mgr.is_installed(PACKAGE):
        report.add_module(
            name=NAME,
            commands=[f"install {PACKAGE}"],
            output="",
            severity="Info",
            notes=f"Package {PACKAGE} could not be installed."
        )
        return

    command = "lynis audit system --quick --no-colors"
    stdout, stderr, code = ssh.execute(command, sudo=True, timeout=300)

    output = stdout
    if stderr.strip():
        output += "\n\n[stderr]\n" + stderr

    report.add_module(
        name=NAME,
        commands=[command],
        output=output,
        severity="Info",
        notes=None if code == 0 else f"lynis exited with code {code}"
    )