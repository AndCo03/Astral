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

## Requirements

### Target Server
* SSH access enabled.
* User account with `sudo` privileges.

### Local Machine (Scanning Host)
* Python installed.
* SSH client installed.
* **Paramiko** library installed for SSH management (`pip install paramiko`).

## Usage
### Installation
```bash
git clone https://github.com/AndCo03/Astral.git
pip install paramiko
```
Astral can be used interactively (wizard) or via command-line flags. In all cases, you need SSH access to the target server with a user that has sudo privileges.
1. **Copy your public SSH key to the target (recommended)**
Copy your public key to the target to enable key-based authentication:
```bash
# Fill in the placeholders between the `<>` brackets with your target and SSH credentials:
ssh-copy-id -i ~/.ssh/<host_ssh_key> <target_user>@<target_ip>
```
2. **Move inside the correct directory**
3. **Run the ASTRAL assessment toolkit**
```bash
python main.py
```
The wizard will prompt you for:
* Target (user@host)
* Username (if not included in the target)
* Authentication method (auto-detects SSH keys in ~/.ssh, or asks for a password)
* Sudo password (with retry)
* Confirmation before starting

**Otherwise**
You can supply all connection details directly:
```bash
python main.py <target_user@target_ip> --key ~/.ssh/<your_key> --sudo-pass 'password' -y
```
**Command-line flags**
| Flag | Description | Default |
| ----- | ----- | ----- |
|target | Positional argument in user@host form. Can be used instead of --host and --user | - |

<br>
Last update: 15/10/2026 - v1.16.0