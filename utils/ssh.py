"""
SSH module for the Linux audit tool.
Handles connection, command execution, and sudo support.
"""

import socket
import paramiko


class SudoError(Exception):
    """Raised when a sudo command fails due to authentication or permission issues."""
    pass


class SSHSession:
    """
    Manages an SSH connection to a remote host.
    Allows executing commands, optionally with sudo.
    """

    def __init__(self, host, port=22, username=None, password=None,
                 key_filename=None, timeout=10):
        """
        Initialize the SSH session parameters.

        :param host: Remote hostname or IP.
        :param port: SSH port, default 22.
        :param username: SSH username.
        :param password: SSH password (optional if key_filename is provided).
        :param key_filename: Path to private key file (optional).
        :param timeout: Connection and command timeout in seconds.
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_filename = key_filename
        self.timeout = timeout
        self.client = None
        self.sudo_password = None

    def connect(self):
        """
        Establish the SSH connection.
        Raises an exception if connection fails.
        """
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                key_filename=self.key_filename,
                timeout=self.timeout,
                look_for_keys=False if self.password else True,
                allow_agent=False if self.password else True
            )
        except paramiko.AuthenticationException:
            raise Exception("SSH authentication failed")
        except paramiko.SSHException as e:
            raise Exception(f"SSH connection error: {e}")
        except socket.timeout:
            raise Exception("SSH connection timed out")

    def close(self):
        """Close the SSH connection."""
        if self.client:
            self.client.close()
            self.client = None

    def set_sudo_password(self, password):
        """Store the sudo password in memory."""
        self.sudo_password = password

    def execute(self, command, sudo=False, timeout=None):
        """
        Execute a command on the remote host.

        :param command: Shell command to run.
        :param sudo: If True, run the command with sudo.
        :param timeout: Optional timeout override.
        :return: Tuple (stdout, stderr, exit_code).
        :raises SudoError: If sudo authentication fails.
        :raises Exception: For timeouts or other errors.
        """
        if not self.client:
            raise Exception("SSH session not connected")

        if timeout is None:
            timeout = self.timeout

        if sudo:
            command = f"sudo -S -p '' {command}"

        try:
            # get_pty=False: senza PTY, sudo -S legge la password dalla pipe
            # in modo affidabile. Su Ubuntu/Debian requiretty non è attivo,
            # quindi il PTY non è necessario.
            stdin, stdout, stderr = self.client.exec_command(
                command, timeout=timeout, get_pty=False
            )
        except Exception as e:
            raise Exception(f"Failed to execute command: {e}")

        if sudo:
            try:
                # Scrivi sempre una riga, anche se la password è vuota:
                # sudo -S attende comunque il newline su stdin.
                stdin.write((self.sudo_password or "") + "\n")
                stdin.flush()
            except Exception:
                pass

        try:
            stdout_str = stdout.read().decode('utf-8', errors='replace')
            stderr_str = stderr.read().decode('utf-8', errors='replace')
            exit_code = stdout.channel.recv_exit_status()
        except socket.timeout:
            raise Exception(f"Command timed out after {timeout}s: {command}")

        # Sicurezza: rimuovi la password sudo dall'output catturato,
        # per evitare che finisca nel report.
        if sudo and self.sudo_password:
            stdout_str = stdout_str.replace(self.sudo_password, "********")
            stderr_str = stderr_str.replace(self.sudo_password, "********")

        # Rileva errori di sudo
        if sudo and exit_code != 0:
            sudo_error_patterns = [
                "sorry, try again",
                "incorrect password",
                "a password is required",
                "no askpass program specified",
                "authentication failure",
                "sudo: a terminal is required",
                "sudo: no tty present",
            ]
            stderr_lower = stderr_str.lower()
            if any(pat in stderr_lower for pat in sudo_error_patterns):
                raise SudoError(
                    f"Sudo authentication failed for command: {command}\n"
                    f"stderr: {stderr_str.strip()}"
                )

        return stdout_str, stderr_str, exit_code