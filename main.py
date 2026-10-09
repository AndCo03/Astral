"""
Linux audit tool - main entry point.
Connects via SSH, runs audit modules, generates a Markdown report, cleans up.
"""

import argparse
import getpass
import sys

from utils.ssh import SSHSession
from utils.packages import PackageManager
from utils.report import Report

from modules import system_info
from modules import ports
from modules import lynis
from modules import nmap
from modules import rootkit

# Registry of modules in execution order.
# Each entry: (module, display name)
MODULES = [
    (system_info, system_info.NAME),
    (ports, ports.NAME),
    (lynis, lynis.NAME),
    (nmap, nmap.NAME),
    (rootkit, rootkit.NAME)
]


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Linux audit tool for remote risk assessment."
    )
    parser.add_argument("--host", required=True, help="Remote hostname or IP.")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22).")
    parser.add_argument("--user", required=True, help="SSH username.")
    parser.add_argument("--password", help="SSH password (optional if using a key).")
    parser.add_argument("--key", help="Path to SSH private key file.")
    parser.add_argument("--sudo-pass", help="Sudo password (prompted if not provided).")
    parser.add_argument("--timeout", type=int, default=15,
                        help="SSH connection timeout in seconds (default: 15).")
    return parser.parse_args()


def main():
    args = parse_args()

    ssh = SSHSession(
        host=args.host,
        port=args.port,
        username=args.user,
        password=args.password,
        key_filename=args.key,
        timeout=args.timeout,
    )

    print(f"[*] Connecting to {args.host}:{args.port} as {args.user}...")
    try:
        ssh.connect()
    except Exception as e:
        print(f"[!] Connection failed: {e}")
        sys.exit(1)
    print("[+] Connected.")

    # Sudo password: use CLI flag if provided, otherwise prompt once.
    sudo_pass = args.sudo_pass
    if not sudo_pass:
        try:
            sudo_pass = getpass.getpass("[?] Sudo password (leave empty if passwordless): ")
        except Exception:
            sudo_pass = ""
    ssh.set_sudo_password(sudo_pass)

    # Detect OS
    pkg_mgr = PackageManager(ssh)
    try:
        distro_id, distro_version, pkg_manager = pkg_mgr.detect_os()
        print(f"[+] Detected OS: {distro_id} {distro_version} (pkg manager: {pkg_manager})")
    except Exception as e:
        print(f"[!] OS detection failed: {e}")
        ssh.close()
        sys.exit(1)

    # Initialize report
    report = Report(host=args.host, distro_id=distro_id, distro_version=distro_version)

    # Update package cache once before installing anything
    print("[*] Updating package cache...")
    try:
        pkg_mgr.update_cache()
    except Exception as e:
        print(f"[!] Package cache update failed: {e}")

    # Run modules in order, each independently
    for module, display_name in MODULES:
        print(f"[*] Running module: {display_name}")
        try:
            module.run(ssh, report, pkg_mgr)
        except Exception as e:
            report.add_module(
                name=display_name,
                commands=[],
                output="",
                severity="Info",
                notes=f"Module crashed: {e}"
            )
            print(f"[!] Module {display_name} failed: {e}")
        else:
            print(f"[+] Module {display_name} completed.")

    # Cleanup: remove only packages installed by this tool
    print("[*] Cleaning up installed packages...")
    try:
        pkg_mgr.cleanup()
    except Exception as e:
        print(f"[!] Cleanup error: {e}")

    # Save report
    try:
        path = report.save(base_dir="reports")
        print(f"[+] Report saved to: {path}")
    except Exception as e:
        print(f"[!] Failed to save report: {e}")
        ssh.close()
        sys.exit(1)

    ssh.close()
    print("[+] Done.")


if __name__ == "__main__":
    main()