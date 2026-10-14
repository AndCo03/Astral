"""
Open ports module for the Linux audit tool.
Lists listening ports using ss.
"""

NAME = "Open Ports"

# Porte considerate pericolose se in ascolto
DANGEROUS_PORTS = {21, 23, 25, 135, 139, 445, 3389}

def _parse_ports(output):
    """Estrae i numeri di porta dall'output di `ss -tulpn`."""
    ports = set()
    for line in output.splitlines():
        # Cerca pattern tipo "0.0.0.0:22" o "*:22"
        if ':' in line:
            parts = line.split()
            for part in parts:
                if ':' in part:
                    # Prende l'ultima parte dopo i due punti
                    port_str = part.rsplit(':', 1)[-1]
                    if port_str.isdigit():
                        ports.add(int(port_str))
    return ports

def _determine_severity(ports):
    """Restituisce (severity, note) in base alle porte trovate."""
    if not ports:
        return "Info", "Nessuna porta in ascolto rilevata."
    
    dangerous_found = ports & DANGEROUS_PORTS
    if dangerous_found:
        return "High", f"Porte pericolose in ascolto: {', '.join(map(str, sorted(dangerous_found)))}"
    
    if len(ports) > 10:
        return "Low", f"Numero elevato di porte in ascolto ({len(ports)})."
    
    return "Info", f"{len(ports)} porte in ascolto, nessuna critica."

def run(ssh, report, pkg_mgr):
    command = "ss -tulpn"
    stdout, stderr, code = ssh.execute(command, sudo=True, timeout=30)

    output = stdout
    if stderr.strip():
        output += "\n\n[stderr]\n" + stderr

    ports = _parse_ports(stdout)
    severity, notes = _determine_severity(ports)

    if code != 0:
        notes = (notes + " " if notes else "") + f"ss exited with code {code}"

    report.add_module(
        name=NAME,
        commands=[command],
        output=output,
        severity=severity,
        notes=notes
    )