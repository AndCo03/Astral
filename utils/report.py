"""
Markdown report generation for the Linux audit tool.
Produces two reports: a technical one (commands + raw output)
and a risk assessment one (score, matrix, priorities).
"""

import os
from datetime import datetime


# Pesi per il calcolo dello score di sicurezza
SEVERITY_WEIGHTS = {
    "Critical": 40,
    "High": 20,
    "Medium": 10,
    "Low": 5,
    "OK": 0,
    "Info": 0,
}

# Mappatura severity -> (probabilità, impatto) di default
SEVERITY_TO_RISK = {
    "Critical": ("High", "Critical"),
    "High":     ("High", "High"),
    "Medium":   ("Medium", "Medium"),
    "Low":      ("Low", "Low"),
    "OK":       ("Low", "Low"),
    "Info":     ("N/D", "N/D"),
}


def _rating_from_score(score):
    """Converte lo score numerico in un giudizio qualitativo."""
    if score >= 90:
        return "Excellent"
    if score >= 75:
        return "Good"
    if score >= 50:
        return "Sufficient"
    if score >= 25:
        return "Poor"
    return "Critical"


class Report:
    """
    Accumulates audit results and generates two Markdown reports:
    a technical one and a risk assessment one.
    """

    def __init__(self, host, distro_id=None, distro_version=None):
        self.host = host
        self.distro_id = distro_id
        self.distro_version = distro_version
        self.start_time = datetime.now()
        self.modules = []

    def add_module(self, name, commands, output, severity="Info",
                   notes=None, probability=None, impact=None):
        """
        Add a module result to the report.

        :param probability: Opzionale. Se None, derivata dalla severity.
        :param impact: Opzionale. Se None, derivato dalla severity.
        """
        self.modules.append({
            "name": name,
            "commands": commands if isinstance(commands, list) else [commands],
            "output": output,
            "severity": severity,
            "notes": notes or "",
            "probability": probability,
            "impact": impact,
        })

    # ---------------- helpers ----------------

    def _compute_score(self):
        score = 100
        for mod in self.modules:
            score -= SEVERITY_WEIGHTS.get(mod["severity"], 0)
        return max(0, score)

    def _severity_counts(self):
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "OK": 0, "Info": 0}
        for mod in self.modules:
            sev = mod["severity"]
            if sev in counts:
                counts[sev] += 1
        return counts

    def _risk_for(self, mod):
        """Restituisce (probability, impact) con fallback sulla severity."""
        prob = mod["probability"]
        imp = mod["impact"]
        if not prob or not imp:
            default_prob, default_imp = SEVERITY_TO_RISK.get(
                mod["severity"], ("Bassa", "Basso")
            )
            prob = prob or default_prob
            imp = imp or default_imp
        return prob, imp

    def _priority_for(self, severity):
        return {
            "Critical": "P1 - Immediate",
            "High":     "P2 - High",
            "Medium":   "P3 - Medium",
            "Low":      "P4 - Low",
            "OK":       "P5 - Low",
            "Info":     "P5 - Informational",
        }.get(severity, "P5 - Informational")

    def _recommendation_for(self, mod):
        """Suggerimento testuale in base al modulo e alla severity."""
        name = mod["name"]
        sev = mod["severity"]

        if "Rootkit" in name and sev in ("Critical", "High"):
            return ("Isolate host from network and analyze files. "
                    "e ripristinare da un backup attendibile.")
        if ("Nmap" in name or "Ports" in name) and sev in ("High", "Medium"):
            return ("Close or filter unnecessary ports via firewall "
                    "(ufw/iptables) and verify exposed services.")
        if "Lynis" in name and sev in ("High", "Medium"):
            return ("Apply the hardening recommendations of Lynis, "
                    "starting from the warnings with highest impact.")
        if sev == "Critical":
            return "Immediate intervention required."
        if sev == "High":
            return "Prioritized intervention within 24-48 hours."
        if sev == "Medium":
            return "Prioritized intervention within 1-2 weeks."
        if sev == "Low":
            return "Recommended improvement, not urgent."
        if sev == "OK":
            return "System appears to be in good condition."
        return "No action required."

    # ---------------- technical report ----------------

    def generate_technical(self):
        lines = []
        lines.append("# Technical Report")
        lines.append("")
        lines.append(f"- **IP:** {self.host}")
        lines.append(f"- **Date:** {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        if self.distro_id:
            distro_str = self.distro_id
            if self.distro_version:
                distro_str += f" {self.distro_version}"
            lines.append(f"- **Distribution:** {distro_str}")
        lines.append("")
        lines.append("---")
        lines.append("")

        for mod in self.modules:
            lines.append(f"## {mod['name']}")
            lines.append("")
            lines.append(f"**Severity:** {mod['severity']}")
            lines.append("")
            lines.append("### Commands")
            lines.append("")
            lines.append("```bash")
            for cmd in mod["commands"]:
                lines.append(cmd)
            lines.append("```")
            lines.append("")
            lines.append("### Raw Output")
            lines.append("")
            lines.append("```")
            lines.append(mod["output"].strip() if mod["output"] else "(no output)")
            lines.append("```")
            lines.append("")
            if mod["notes"]:
                lines.append(f"**Notes:** {mod['notes']}")
                lines.append("")
            lines.append("---")
            lines.append("")

        return "\n".join(lines)

    # ---------------- risk assessment ----------------

    def generate_risk(self):
        score = self._compute_score()
        rating = _rating_from_score(score)
        counts = self._severity_counts()

        lines = []
        lines.append("# Risk Assessment Report")
        lines.append("")
        lines.append(f"- **IP:** {self.host}")
        lines.append(f"- **Date:** {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        if self.distro_id:
            distro_str = self.distro_id
            if self.distro_version:
                distro_str += f" {self.distro_version}"
            lines.append(f"- **Distribution:** {distro_str}")
        lines.append("")

        # --- Security score ---
        lines.append("## Security Score")
        lines.append("")
        lines.append(f"**{score}/100 — {rating}**")
        lines.append("")
        lines.append("> Score = 100 − sum of weights per severity "
                     "(Critical −40, High −20, Medium −10, Low −5, Info 0), with floor at 0.")
        lines.append("")

        # --- Severity breakdown ---
        lines.append("## Severity Breakdown")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ("Critical", "High", "Medium", "Low", "OK","Info"):
            lines.append(f"| {sev} | {counts[sev]} |")
        lines.append("")

        # --- Risk matrix ---
        lines.append("## Risk Matrix (Probability × Impact)")
        lines.append("")
        lines.append("| Module | Severity | Probability | Impact | Priority |")
        lines.append("|--------|----------|-------------|--------|----------|")
        for mod in self.modules:
            prob, imp = self._risk_for(mod)
            priority = self._priority_for(mod["severity"])
            lines.append(
                f"| {mod['name']} | {mod['severity']} | {prob} | {imp} | {priority} |"
            )
        lines.append("")

        # --- Top criticalities ---
        urgent = [m for m in self.modules
                  if m["severity"] in ("Critical", "High", "Medium")]
        urgent.sort(key=lambda m: SEVERITY_WEIGHTS.get(m["severity"], 0), reverse=True)

        lines.append("## Top Criticalities")
        lines.append("")
        if not urgent:
            lines.append("No significant criticalities found. The system appears to be in good condition.")
            lines.append("")
        else:
            for i, mod in enumerate(urgent, 1):
                prob, imp = self._risk_for(mod)
                lines.append(f"### {i}. {mod['name']} — {mod['severity']}")
                lines.append("")
                lines.append(f"- **Probability:** {prob}")
                lines.append(f"- **Impact:** {imp}")
                lines.append(f"- **Priority:** {self._priority_for(mod['severity'])}")
                if mod["notes"]:
                    lines.append(f"- **Notes:** {mod['notes']}")
                lines.append(f"- **Recommendation:** {self._recommendation_for(mod)}")
                lines.append("")

        # --- Recommendations summary ---
        lines.append("## Recommendations")
        lines.append("")
        seen = set()
        for mod in urgent:
            rec = self._recommendation_for(mod)
            if rec not in seen:
                seen.add(rec)
                lines.append(f"- **{mod['name']}:** {rec}")
        if not seen:
            lines.append("- No recommendations: no significant criticalities found.")
        lines.append("")

        # --- Methodology ---
        lines.append("## Methodology")
        lines.append("")
        lines.append("- **Severity**: assigned by specific heuristics per module "
                     "(dangerous ports, Lynis warnings, rootkit keywords).")
        lines.append("- **Probability / Impact**: derived from severity, "
                     "except for overrides provided by the module.")
        lines.append("- **Score**: 100 − sum of weights per severity, with floor at 0.")
        lines.append("")

        return "\n".join(lines)

    # ---------------- save ----------------

    def save(self, base_dir="reports"):
        """
        Save both reports in a timestamped folder.

        :return: Path to the report directory.
        """
        timestamp = self.start_time.strftime("%Y-%m-%d_%H-%M-%S")
        report_dir = os.path.join(base_dir, timestamp)
        os.makedirs(report_dir, exist_ok=True)

        technical_path = os.path.join(report_dir, "technical_report.md")
        risk_path = os.path.join(report_dir, "risk_assessment.md")

        with open(technical_path, "w", encoding="utf-8") as f:
            f.write(self.generate_technical())

        with open(risk_path, "w", encoding="utf-8") as f:
            f.write(self.generate_risk())

        return report_dir