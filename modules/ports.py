"""
Open ports module for the Linux audit tool.
Lists listening ports using ss.
"""

NAME = "Open Ports"

# Ports considered dangerous if listening.
DANGEROUS_PORTS = {21, 23, 25, 135, 139, 445, 3389}


def _parse_ports(output):
    """Extract port numbers from the output of `ss -tulpn`."""
    ports = set()
    for line in output.splitlines():
        if ':' in line:
            parts = line.split()
            for part in parts:
                if ':' in part:
                    port_str = part.rsplit(':', 1)[-1]
                    if port_str.isdigit():
                        ports.add(int(port_str))
    return ports


def _determine_severity(ports):
    """Returns (severity, note) based on the found ports."""
    if not ports:
        return "N/D", "No listening ports found."

    dangerous_found = ports & DANGEROUS_PORTS
    if dangerous_found:
        return "High", (f"Dangerous ports listening: "
                        f"{', '.join(map(str, sorted(dangerous_found)))}")

    if len(ports) > 10:
        return "Low", f"High number of listening ports ({len(ports)})."

    return "OK", f"{len(ports)} listening ports, no critical issues."


def _determine_probability(ports):
    """
    Probability of exploitation based on the exposure surface.

    - Dangerous ports open -> High
    - Many services (> 10) -> Medium
    - Few services -> Low
    - No services -> Low
    """
    if not ports:
        return "N/D"
    dangerous_found = ports & DANGEROUS_PORTS
    if dangerous_found:
        return "High"
    if len(ports) > 10:
        return "Medium"
    return "Low"


def run(ssh, report, pkg_mgr):
    command = "ss -tulpn"
    stdout, stderr, code = ssh.execute(command, sudo=True, timeout=30)

    output = stdout
    if stderr.strip():
        output += "\n\n[stderr]\n" + stderr

    ports = _parse_ports(stdout)
    severity, notes = _determine_severity(ports)
    probability = _determine_probability(ports)

    if code != 0:
        notes = (notes + " " if notes else "") + f"ss exited with code {code}"

    report.add_module(
        name=NAME,
        commands=[command],
        output=output,
        severity=severity,
        notes=notes,
        probability=probability,
    )