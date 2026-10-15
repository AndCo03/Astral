"""
Linux audit tool - main entry point.
Connects via SSH, runs audit modules, generates a Markdown report, cleans up.
"""

import argparse
import getpass
import sys

from utils.ssh import SSHSession, SudoError
from utils.packages import PackageManager
from utils.report import Report

from modules import system_info
from modules import ports
from modules import lynis
from modules import nmap
from modules import rootkit
from modules import debsecan
from modules import les
from modules import trivy
from modules import ssh_audit

# Registry of modules in execution order.
# Each entry: (module, display name)
MODULES = [
    (system_info, system_info.NAME),
    (ports, ports.NAME),
    (lynis, lynis.NAME),
    (les, les.NAME),
    (trivy, trivy.NAME),
    (ssh_audit, ssh_audit.NAME),
    (debsecan, debsecan.NAME),
    (nmap, nmap.NAME),
    (rootkit, rootkit.NAME),
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
    parser.add_argument("--no-sudo", action="store_true",
                        help="Skip all modules that require sudo, without prompting.")
    parser.add_argument("--timeout", type=int, default=15,
                        help="SSH connection timeout in seconds (default: 15).")
    return parser.parse_args()


def _resolve_sudo(args, ssh):
    """
    Determine whether sudo is usable, prompting for a password (with one retry)
    if needed. Returns True if sudo is confirmed working, False otherwise.
    """
    # --no-sudo: skip completely.
    if args.no_sudo:
        print("[~] --no-sudo specified: sudo modules will be skipped.")
        return False

    # Sudo password: use CLI flag if provided, otherwise prompt once.
    sudo_pass = args.sudo_pass
    prompted = False
    if sudo_pass is None:
        try:
            sudo_pass = getpass.getpass("[?] Sudo password (leave empty if passwordless): ")
            prompted = True
        except Exception:
            sudo_pass = ""
    ssh.set_sudo_password(sudo_pass)

    print("[***] Verifying sudo access...")
    if ssh.check_sudo():
        print("[o] Sudo access confirmed.")
        return True

    # If the password was provided via CLI, don't retry: the user's intent is clear.
    if not prompted:
        print("[!] Sudo authentication failed (password provided via --sudo-pass).")
        print("[!] Modules requiring sudo will be skipped.")
        return False

    # Interactive: offer one retry.
    try:
        retry = getpass.getpass(
            "[?] Sudo authentication failed. Retry password "
            "(leave empty to skip sudo modules): "
        )
    except Exception:
        retry = ""

    if retry:
        ssh.set_sudo_password(retry)
        if ssh.check_sudo():
            print("[o] Sudo access confirmed on retry.")
            return True

    print("[!] Sudo authentication failed.")
    print("[!] Modules requiring sudo will be skipped.")
    print("    Only non-sudo modules will run; see the report for details.")
    return False


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

    print(f"[***] Connecting to {args.host}:{args.port} as {args.user}...")
    try:
        ssh.connect()
    except Exception as e:
        print(f"[!] Connection failed: {e}")
        sys.exit(1)
    print("[o] Connected.")

    # Pre-flight: figure out whether sudo is usable before running anything.
    sudo_ok = _resolve_sudo(args, ssh)

    # Detect OS (does not require sudo).
    pkg_mgr = PackageManager(ssh)
    try:
        distro_id, distro_version, pkg_manager = pkg_mgr.detect_os()
        print(f"[o] Detected OS: {distro_id} {distro_version} (pkg manager: {pkg_manager})")
    except Exception as e:
        print(f"[!] OS detection failed: {e}")
        ssh.close()
        sys.exit(1)

    # Initialize report.
    report = Report(host=args.host, distro_id=distro_id, distro_version=distro_version)

    # Update package cache only if we will actually install anything.
    if sudo_ok:
        print("[***] Updating package cache...")
        try:
            pkg_mgr.update_cache()
        except Exception as e:
            print(f"[!] Package cache update failed: {e}")

    # Run modules in order, skipping those that require sudo when unavailable.
    for module, display_name in MODULES:
        requires_sudo = getattr(module, "REQUIRES_SUDO", True)

        if requires_sudo and not sudo_ok:
            print(f"[~] Skipping module (requires sudo): {display_name}")
            report.add_module(
                name=display_name,
                commands=[],
                output="",
                severity="N/D",
                notes="Skipped: sudo authentication failed or not available."
            )
            continue

        print(f"[***] Running module: {display_name}")
        try:
            module.run(ssh, report, pkg_mgr)
        except SudoError as e:
            report.add_module(
                name=display_name,
                commands=[],
                output="",
                severity="High",
                notes=f"Sudo authentication failed: {e}"
            )
            print(f"[!] Sudo error in module {display_name}: {e}")
        except Exception as e:
            report.add_module(
                name=display_name,
                commands=[],
                output="",
                severity="ERROR",
                notes=f"Module crashed: {e}"
            )
            print(f"[!] Module {display_name} failed: {e}")
        else:
            print(f"[o] Module {display_name} completed.")

    # Cleanup: only if sudo was available (otherwise nothing was installed).
    if sudo_ok:
        print("[***] Cleaning up installed packages...")
        try:
            pkg_mgr.cleanup()
        except Exception as e:
            print(f"[!] Cleanup error: {e}")

    # Save report.
    try:
        path = report.save(base_dir="reports")
        print(f"[+] Report saved to: {path}")
    except Exception as e:
        print(f"[!] Failed to save report: {e}")
        ssh.close()
        sys.exit(1)

    ssh.close()
    print("[o] Done.")


if __name__ == "__main__":
    main()