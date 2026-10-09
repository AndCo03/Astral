"""
Open ports module for the Linux audit tool.
Lists listening ports using ss.
"""


NAME = "Open Ports"


def run(ssh, report, pkg_mgr):
    """
    List listening TCP/UDP ports and associated processes.

    :param ssh: SSHSession instance.
    :param report: Report instance.
    :param pkg_mgr: Shared PackageManager instance.
    """
    command = "ss -tulpn"
    stdout, stderr, code = ssh.execute(command, sudo=True, timeout=30)

    output = stdout
    if stderr.strip():
        output += "\n\n[stderr]\n" + stderr

    report.add_module(
        name=NAME,
        commands=[command],
        output=output,
        severity="Info",
        notes=None if code == 0 else f"ss exited with code {code}"
    )