"""
Linux audit tool - main entry point.
Connects via SSH, runs audit modules, generates a Markdown report, cleans up.
"""

import argparse
import getpass
import json
import os
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

STARTUP_ART = r"""         .                      .
         .                      ;
         :                  - --+- -
         !           .          !
         |        .             .
         |_         +
      ,  | `.
--- --+-<+>-+- ---  --  -
      `._|_,'
         T
         |
         !
         :         . :
         .       *
    _         _             _ 
   / \   ___ | |_ _ __ __ _| |
  / _ \ / __|| __| '__/ _` | |
 / ___ \\__ \| |_| | | (_| | |
/_/   \_\___/ \__|_|  \__,_|_|
Automated Server Toolkit for Remote Assessment on Linux
v1.16.0
         """

# --- Config persistence (profiles) ---
CONFIG_DIR = os.path.expanduser("~/.astral")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")

# --- SSH key auto-detection (in order of preference) ---
DEFAULT_KEYS = [
    "~/.ssh/id_ed25519",
    "~/.ssh/id_rsa",
    "~/.ssh/id_ecdsa",
]


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Linux audit tool for remote risk assessment.",
        epilog=(
            "examples:\n"
            "  python main.py                          # interactive wizard\n"
            "  python main.py admin@192.168.1.10       # auto-detects SSH key\n"
            "  python main.py --profile prod           # load a saved profile\n"
            "  python main.py admin@10.0.0.1 --save prod\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", nargs="?",
                        help="Target in 'user@host' form (optional shortcut).")
    parser.add_argument("--host", help="Remote hostname or IP.")
    parser.add_argument("--port", type=int, default=None,
                        help="SSH port (default: 22).")
    parser.add_argument("--user", help="SSH username.")
    parser.add_argument("--password", help="SSH password (optional if using a key).")
    parser.add_argument("--key", help="Path to SSH private key file.")
    parser.add_argument("--sudo-pass", help="Sudo password (prompted if not provided).")
    parser.add_argument("--no-sudo", action="store_true",
                        help="Skip all modules that require sudo, without prompting.")
    parser.add_argument("--timeout", type=int, default=15,
                        help="SSH connection timeout in seconds (default: 15).")
    parser.add_argument("--profile", metavar="NAME",
                        help="Load a saved connection profile.")
    parser.add_argument("--save", metavar="NAME",
                        help="Save the resolved connection as a named profile.")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="Skip the confirmation prompt.")
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Interactive helpers
# ---------------------------------------------------------------------------

def _prompt(text, default=None, password=False):
    """Prompt the user for a value, optionally with a default."""
    suffix = f" [{default}]" if default is not None else ""
    while True:
        try:
            if password:
                val = getpass.getpass(f"{text}{suffix}: ")
            else:
                val = input(f"{text}{suffix}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(1)
        if val:
            return val
        if default is not None:
            return default
        print("  [!] This field is required.")


def _detect_keys():
    """Return the list of SSH private keys found in ~/.ssh."""
    return [k for k in DEFAULT_KEYS if os.path.isfile(os.path.expanduser(k))]


# ---------------------------------------------------------------------------
# Profile management
# ---------------------------------------------------------------------------

def _load_profile(name):
    if not os.path.isfile(CONFIG_FILE):
        print(f"[!] No saved profiles (expected at {CONFIG_FILE}).")
        sys.exit(1)
    try:
        with open(CONFIG_FILE) as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] Could not read profiles: {e}")
        sys.exit(1)
    if name not in data:
        available = ", ".join(data.keys()) or "(none)"
        print(f"[!] Profile '{name}' not found. Available: {available}")
        sys.exit(1)
    return data[name]


def _save_profile(name, args):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    data = {}
    if os.path.isfile(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f:
                data = json.load(f)
        except Exception:
            data = {}
    # NOTE: passwords are intentionally never persisted.
    data[name] = {
        "host": args.host,
        "user": args.user,
        "port": args.port,
        "key": args.key,
    }
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(data, f, indent=2)
        os.chmod(CONFIG_FILE, 0o600)
        print(f"[o] Profile '{name}' saved.")
    except Exception as e:
        print(f"[!] Could not save profile: {e}")


# ---------------------------------------------------------------------------
# Connection resolution
# ---------------------------------------------------------------------------

def _parse_target(target):
    """Split 'user@host' → (user, host)."""
    if "@" in target:
        u, h = target.rsplit("@", 1)
        return u, h
    return None, target


def _resolve_connection(args):
    """Fill in host/user/port/key/password from CLI, profile, or interactive prompts."""
    # 1. Load profile if requested (explicit CLI flags take precedence)
    if args.profile:
        prof = _load_profile(args.profile)
        args.host = args.host or prof.get("host")
        args.user = args.user or prof.get("user")
        if args.port is None:
            args.port = prof.get("port")
        args.key = args.key or prof.get("key")
        print(f"[o] Loaded profile '{args.profile}'.")

    # 2. Parse the user@host positional shortcut
    if args.target:
        u, h = _parse_target(args.target)
        args.host = args.host or h
        if u:
            args.user = args.user or u

    # 3. Default port
    if args.port is None:
        args.port = 22

    # 4. Interactive prompts for anything still missing
    setup_needed = not (args.host and args.user)
    if setup_needed:
        print("\n[i] Interactive setup (Ctrl+C to abort)")

    if not args.host:
        target = _prompt("Target (user@ip)")
        u, h = _parse_target(target)
        args.host = h
        if u and not args.user:
            args.user = u
    if not args.user:
        args.user = _prompt("Username")

    # 5. Authentication: auto-detect keys, offer password fallback
    if not args.key and not args.password:
        keys = _detect_keys()
        if keys:
            print(f"\n[i] Detected SSH key: {keys[0]}")
            if len(keys) > 1:
                print("[?] Multiple keys found:")
                for i, k in enumerate(keys, 1):
                    print(f"    {i}) {k}")
                idx = _prompt("Choose key", default="1")
                try:
                    args.key = keys[int(idx) - 1]
                except (ValueError, IndexError):
                    args.key = keys[0]
            else:
                args.key = keys[0]
            use_pass = _prompt("Use password instead? (y/N)", default="N").lower()
            if use_pass in ("y", "yes"):
                args.key = None
                args.password = getpass.getpass("[?] SSH password: ")
        else:
            print("\n[i] No SSH keys found in ~/.ssh — password required.")
            args.password = getpass.getpass("[?] SSH password: ")


def _confirm(args):
    """Show a summary and ask the user to confirm."""
    print("\n[i] Connection summary")
    print(f"    Target: {args.user}@{args.host}:{args.port}")
    if args.key:
        print(f"    Auth:   SSH key ({args.key})")
    elif args.password:
        print(f"    Auth:   Password")
    print(f"    Sudo:   {'disabled (--no-sudo)' if args.no_sudo else 'will be requested'}")
    if args.save:
        print(f"    Save:   profile '{args.save}' will be stored in {CONFIG_FILE}")
    ans = _prompt("Proceed with the audit? (Y/n)", default="Y").lower()
    if ans not in ("y", "yes"):
        print("[i] Aborted by user.")
        sys.exit(0)


# ---------------------------------------------------------------------------
# Sudo resolution
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()
    print(STARTUP_ART)

    # Fill in missing connection details (profile → positional → prompts).
    _resolve_connection(args)

    # Confirmation summary (skipped with -y).
    if not args.yes:
        _confirm(args)

    # Persist the resolved connection, if the user asked for it.
    if args.save:
        _save_profile(args.save, args)

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