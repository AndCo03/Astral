"""
Markdown report generation for the Linux audit tool.
Collects results from modules and writes a timestamped report.
"""

import os
from datetime import datetime


class Report:
    """
    Accumulates audit results and generates a Markdown report.
    """

    def __init__(self, host, distro_id=None, distro_version=None):
        """
        Initialize the report with target metadata.

        :param host: Target hostname or IP.
        :param distro_id: Detected distribution ID (optional).
        :param distro_version: Detected distribution version (optional).
        """
        self.host = host
        self.distro_id = distro_id
        self.distro_version = distro_version
        self.start_time = datetime.now()
        self.modules = []

    def add_module(self, name, commands, output, severity="Info", notes=None):
        """
        Add a module result to the report.

        :param name: Module name (e.g., "System Info", "Ports").
        :param commands: List of command strings executed.
        :param output: Raw output (stdout + stderr) as a single string.
        :param severity: Severity level: Info, Low, Medium, High, Critical.
        :param notes: Optional additional notes or error messages.
        """
        self.modules.append({
            "name": name,
            "commands": commands if isinstance(commands, list) else [commands],
            "output": output,
            "severity": severity,
            "notes": notes or ""
        })

    def _severity_order(self, severity):
        """Return a numeric value for sorting severities."""
        order = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}
        return order.get(severity, 0)

    def generate(self):
        """
        Generate the Markdown report as a string.
        """
        lines = []
        lines.append(f"# Linux Audit Report")
        lines.append("")
        lines.append(f"- **Host:** {self.host}")
        lines.append(f"- **Date:** {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        if self.distro_id:
            distro_str = self.distro_id
            if self.distro_version:
                distro_str += f" {self.distro_version}"
            lines.append(f"- **Distribution:** {distro_str}")
        lines.append("")

        # Executive summary
        lines.append("## Executive Summary")
        lines.append("")
        lines.append("| Module | Severity |")
        lines.append("|--------|----------|")
        for mod in self.modules:
            lines.append(f"| {mod['name']} | {mod['severity']} |")
        lines.append("")

        # Detailed results
        lines.append("## Detailed Results")
        lines.append("")
        for mod in self.modules:
            lines.append(f"### {mod['name']}")
            lines.append("")
            lines.append(f"**Severity:** {mod['severity']}")
            lines.append("")
            lines.append("**Commands executed:**")
            lines.append("")
            lines.append("```bash")
            for cmd in mod["commands"]:
                lines.append(cmd)
            lines.append("```")
            lines.append("")
            lines.append("**Output:**")
            lines.append("")
            lines.append("```")
            lines.append(mod["output"].strip())
            lines.append("```")
            lines.append("")
            if mod["notes"]:
                lines.append(f"**Notes:** {mod['notes']}")
                lines.append("")

        return "\n".join(lines)

    def save(self, base_dir="reports"):
        """
        Save the report to a timestamped Markdown file.

        :param base_dir: Base directory for reports.
        :return: Path to the saved report file.
        """
        timestamp = self.start_time.strftime("%Y-%m-%d_%H-%M-%S")
        report_dir = os.path.join(base_dir, timestamp)
        os.makedirs(report_dir, exist_ok=True)

        report_path = os.path.join(report_dir, "audit_report.md")
        content = self.generate()

        with open(report_path, "w", encoding="utf-8") as f:
            f.write(content)

        return report_path