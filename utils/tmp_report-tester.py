"""
Temporary test script for utils/report.py
"""

from report import Report


def main():
    report = Report(host="192.168.1.20", distro_id="ubuntu", distro_version="22.04")

    # Simula un modulo "System Info"
    report.add_module(
        name="System Info",
        commands=[
            "hostname",
            "lsb_release -a",
            "uname -r"
        ],
        output=(
            "test-server\n"
            "Distributor ID:\tUbuntu\n"
            "Description:\tUbuntu 22.04.3 LTS\n"
            "Release:\t22.04\n"
            "Codename:\tjammy\n"
            "5.15.0-91-generic\n"
        ),
        severity="Info"
    )

    # Simula un modulo "Ports" con una severità più alta
    report.add_module(
        name="Open Ports",
        commands=["ss -tulpn"],
        output=(
            "Netid State  Local Address:Port  Process\n"
            "tcp   LISTEN 0.0.0.0:22          sshd\n"
            "tcp   LISTEN 0.0.0.0:80          nginx\n"
        ),
        severity="Medium",
        notes="Port 80 exposed on all interfaces."
    )

    # Simula un modulo fallito
    report.add_module(
        name="Rootkit Check",
        commands=["chkrootkit"],
        output="",
        severity="Info",
        notes="Command failed: chkrootkit not installed."
    )

    path = report.save(base_dir="reports")
    print(f"Report saved to: {path}")


if __name__ == "__main__":
    main()