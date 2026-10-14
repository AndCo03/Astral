"""
Package management utilities for the Linux audit tool.
Detects the distribution and package manager, installs and removes packages.
"""

def _major_version(version_str):
    """Estrae la versione major come intero. Restituisce 0 se non parsabile."""
    try:
        return int(str(version_str).split('.')[0])
    except (ValueError, AttributeError):
        return 0

class PackageManager:
    """
    Manages package installation and removal on the remote host.
    Tracks packages installed by this tool for later cleanup.
    """

    def __init__(self, ssh_session):
        self.ssh = ssh_session
        self.distro_id = None
        self.distro_version = None
        self.pkg_manager = None
        self.installed_by_tool = set()

    def detect_os(self):
        stdout, stderr, code = self.ssh.execute("cat /etc/os-release")
        if code != 0:
            raise Exception("Failed to read /etc/os-release")

        info = {}
        for line in stdout.splitlines():
            if '=' in line:
                key, value = line.split('=', 1)
                info[key.strip()] = value.strip().strip('"')

        self.distro_id = info.get('ID', '').lower()
        self.distro_version = info.get('VERSION_ID', '')

        if self.distro_id in ('debian', 'ubuntu', 'linuxmint', 'pop'):
            self.pkg_manager = 'apt'
        elif self.distro_id in ('fedora', 'rhel', 'centos', 'rocky', 'almalinux'):
            if self.distro_id == 'centos':
                major = _major_version(self.distro_version)
                self.pkg_manager = 'dnf' if major >= 8 else 'yum'
            else:
                self.pkg_manager = 'dnf'
        elif self.distro_id.startswith('opensuse'):
            self.pkg_manager = 'zypper'
        elif self.distro_id == 'arch':
            self.pkg_manager = 'pacman'
        else:
            raise Exception(f"Unsupported distribution: {self.distro_id}")

        return self.distro_id, self.distro_version, self.pkg_manager

    def update_cache(self):
        """Update package manager cache."""
        if self.pkg_manager == 'apt':
            self.ssh.execute("apt update", sudo=True)
        elif self.pkg_manager in ('dnf', 'yum'):
            self.ssh.execute(f"{self.pkg_manager} makecache", sudo=True)
        elif self.pkg_manager == 'zypper':
            self.ssh.execute("zypper refresh", sudo=True)
        elif self.pkg_manager == 'pacman':
            self.ssh.execute("pacman -Sy", sudo=True)

    def is_installed(self, package):
        """Check if a package is already installed."""
        if self.pkg_manager == 'apt':
            cmd = f"dpkg -s {package}"
        elif self.pkg_manager in ('dnf', 'yum'):
            cmd = f"rpm -q {package}"
        elif self.pkg_manager == 'zypper':
            cmd = f"rpm -q {package}"
        elif self.pkg_manager == 'pacman':
            cmd = f"pacman -Q {package}"
        else:
            return False

        stdout, stderr, code = self.ssh.execute(cmd)
        return code == 0

    def install(self, packages):
        """
        Install a list of packages.
        Tracks installed packages for later removal.
        Returns list of successfully installed packages.
        """
        if isinstance(packages, str):
            packages = [packages]

        installed = []
        for pkg in packages:
            if pkg in self.installed_by_tool:
                continue
            if self.is_installed(pkg):
                continue

            if self.pkg_manager == 'apt':
                cmd = f"apt install -y {pkg}"
            elif self.pkg_manager in ('dnf', 'yum'):
                cmd = f"{self.pkg_manager} install -y {pkg}"
            elif self.pkg_manager == 'zypper':
                cmd = f"zypper install -y {pkg}"
            elif self.pkg_manager == 'pacman':
                cmd = f"pacman -S --noconfirm {pkg}"
            else:
                raise Exception(f"Unsupported package manager: {self.pkg_manager}")

            stdout, stderr, code = self.ssh.execute(cmd, sudo=True)
            if code == 0:
                self.installed_by_tool.add(pkg)
                installed.append(pkg)

        return installed

    def cleanup(self):
        """Remove all packages installed by this tool, including config files and orphaned dependencies."""
        if not self.installed_by_tool:
            return

        pkgs = list(self.installed_by_tool)
        for pkg in pkgs:
            if self.pkg_manager == 'apt':
                cmd = f"apt purge -y {pkg}"
            elif self.pkg_manager in ('dnf', 'yum'):
                cmd = f"{self.pkg_manager} remove -y {pkg}"
            elif self.pkg_manager == 'zypper':
                cmd = f"zypper remove -y --clean-deps {pkg}"
            elif self.pkg_manager == 'pacman':
                cmd = f"pacman -Rns --noconfirm {pkg}"
            else:
                continue

            self.ssh.execute(cmd, sudo=True)
            self.installed_by_tool.discard(pkg)

        if self.pkg_manager == 'apt':
            self.ssh.execute("apt autoremove -y", sudo=True)
        elif self.pkg_manager in ('dnf', 'yum'):
            self.ssh.execute(f"{self.pkg_manager} autoremove -y", sudo=True)
        elif self.pkg_manager == 'zypper':
            self.ssh.execute("zypper purge-kernels", sudo=True)
        elif self.pkg_manager == 'pacman':
            pass