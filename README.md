# Astral - Automated Server Toolkit for Remote Assessment on Linux

A lightweight, automated toolkit designed to perform remote security audits and risk assessments on Linux servers over SSH with zero permanent footprint.

## Key Features

* **Remote Audit via SSH:** Connects securely to the target machine without requiring an agent installed beforehand.
* **Smart Dependency Management:** Checks for existing tools on the target system and installs *only* the missing utilities required for the audit.
* **Centralized Reporting:** Generates and aggregates all assessment reports directly on the scanning host.
* **Automatic Cleanup:** Uninstalls all packages downloaded by the toolkit during execution, removes configuration files and automatically installed dependencies, leaving the target server as clean as it was before the scan.

## Workflow

1. **Connect:** Establishes an SSH connection to the target server.
2. **Inspect:** Identifies missing diagnostic packages.
3. **Provision:** Temporarily installs only the missing dependencies.
4. **Execute & Report:** Runs the audit tools and saves reports on the local scanning machine.
5. **Clean Up:** Purges all installed packages and temporary files and orphaned dependencies (best effort, depending on the package manager)from the target machine.

## Prerequisites

* SSH access with `sudo` privileges on the target server.
* Local machine with SSH client installed.
* Paramiko (Dipendence) installed, for ssh connection.

## Usage
Insert between the <> symbles what required:
```bash
ssh-copy-id -i ~/.ssh/<host_public_key> <target_user>@<target_ip>
python main.py --host <target_ip> --user <target_user> --key ~/.ssh/<host_public_key>
```

<br>
Up to Date: 15/10/2026
<br>
Version: 1.8.5