"""
Nmap module for the Linux audit tool.
Runs an nmap scan against localhost.
"""

NAME = "Nmap Localhost Scan"
PACKAGE = "nmap"

DANGEROUS_PORTS = {21, 23, 25, 135, 139, 445, 3389}

def _parse_nmap_ports(output):
    """Estrae le porte aperte dall'output di nmap."""
    ports = set()
    for line in output.splitlines():
        # Cerca righe tipo "22/tcp open  ssh"
        if '/tcp' in line and 'open' in line:
            parts = line.split()
            if parts:
                port_proto = parts[0]
                if '/' in port_proto:
                    port_str = port_proto.split('/')[0]
                    if port_str.isdigit():
                        ports.add(int(port_str))
    return ports

def _determine_severity(ports):
    if not ports:
        return "N/D", "Nessuna porta aperta rilevata da nmap."
    dangerous_found = ports & DANGEROUS_PORTS
    if dangerous_found:
        return "High", f"Porte pericolose aperte: {', '.join(map(str, sorted(dangerous_found)))}"
    if len(ports) > 10:
        return "Low", f"Numero elevato di porte aperte ({len(ports)})."
    return "OK", f"{len(ports)} porte aperte, nessuna critica."

def run(ssh, report, pkg_mgr):
    installed = pkg_mgr.install(PACKAGE)
    if PACKAGE not in installed and not pkg_mgr.is_installed(PACKAGE):
        report.add_module(
            name=NAME,
            commands=[f"install {PACKAGE}"],
            output="",
            severity="N/D",
            notes=f"Package {PACKAGE} could not be installed."
        )
        return

    command = "nmap -sS -sV -O localhost"
    stdout, stderr, code = ssh.execute(command, sudo=True, timeout=300)

    output = stdout
    if stderr.strip():
        output += "\n\n[stderr]\n" + stderr

    ports = _parse_nmap_ports(stdout)
    severity, notes = _determine_severity(ports)

    if code != 0:
        notes = (notes + " " if notes else "") + f"nmap exited with code {code}"

    report.add_module(
        name=NAME,
        commands=[command],
        output=output,
        severity=severity,
        notes=notes
    )