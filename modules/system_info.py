"""
System information module for the Linux audit tool.
Collects basic host information.
"""


NAME = "System Info"


def run(ssh, report, pkg_mgr):
    """
    Collect basic system information: hostname, distro, kernel.

    :param ssh: SSHSession instance.
    :param report: Report instance.
    :param pkg_mgr: Shared PackageManager instance.
    """
    commands = [
        "hostname",
        "lsb_release -a",
        "uname -r",
    ]

    outputs = []
    for cmd in commands:
        stdout, stderr, code = ssh.execute(cmd, sudo=False, timeout=30)
        outputs.append(f"$ {cmd}\n{stdout}")
        if stderr.strip():
            outputs.append(f"[stderr]\n{stderr}")

    report.add_module(
        name=NAME,
        commands=commands,
        output="\n".join(outputs),
        severity="Info"
    )