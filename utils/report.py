"""
Markdown report generation for the Linux audit tool.
Produces two reports: a technical one (commands + raw output)
and a risk assessment one (score, matrix, priorities).
"""

import os
from datetime import datetime


# ---------------------------------------------------------------------------
# Scoring configuration
# ---------------------------------------------------------------------------

# Weights used for the overall security score (higher = worse).
SEVERITY_WEIGHTS = {
    "Critical": 40,
    "High": 20,
    "Medium": 10,
    "Low": 5,
    "OK": 0,
    "Info": 0,
}

# Default (probability, impact) fallback when a module does not provide them.
# Used only if the module does not pass an explicit value.
SEVERITY_TO_RISK = {
    "Critical": ("High", "Critical"),
    "High":     ("High", "High"),
    "Medium":   ("Medium", "Medium"),
    "Low":      ("Low", "Low"),
    "OK":       ("Low", "Low"),
    "Info":     ("N/D", "N/D"),
}

# Ordinal weights used to compute a numeric risk score = P * I.
PROBABILITY_WEIGHTS = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4,
    "N/D": 0,
}

IMPACT_WEIGHTS = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4,
    "N/D": 0,
}


def _rating_from_score(score):
    """Converts the numeric security score into a qualitative rating."""
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

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_module(self, name, commands, output, severity="Info",
                   notes=None, probability=None, impact=None):
        """
        Add a module result to the report.

        :param name: Human-readable module name.
        :param commands: List of commands executed (or a single string).
        :param output: Raw output captured from the target.
        :param severity: One of Critical / High / Medium / Low / OK / Info / N/D.
        :param notes: Optional free-form notes.
        :param probability: Optional independent probability estimate
                            (Low / Medium / High / Critical). If None,
                            it is derived from the severity.
        :param impact: Optional independent impact estimate
                       (Low / Medium / High / Critical). If None,
                       it is derived from the severity.
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

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _compute_score(self):
        """Overall security score (100 - sum of severity weights, floor 0)."""
        score = 100
        for mod in self.modules:
            score -= SEVERITY_WEIGHTS.get(mod["severity"], 0)
        return max(0, score)

    def _severity_counts(self):
        counts = {"Critical": 0, "High": 0, "Medium": 0,
                  "Low": 0, "OK": 0, "Info": 0}
        for mod in self.modules:
            sev = mod["severity"]
            if sev in counts:
                counts[sev] += 1
        return counts

    def _risk_for(self, mod):
        """
        Returns (probability, impact) for a module.

        Uses the explicit values provided by the module when available,
        otherwise falls back to the severity-based mapping.
        """
        prob = mod.get("probability")
        imp = mod.get("impact")

        default_prob, default_imp = SEVERITY_TO_RISK.get(
            mod["severity"], ("Low", "Low")
        )

        if not prob:
            prob = default_prob
        if not imp:
            imp = default_imp

        return prob, imp

    def _risk_score(self, prob, imp):
        """
        Numeric risk score = weight(probability) * weight(impact).

        Result range: 0 (N/D) to 16 (Critical x Critical).
        """
        return (PROBABILITY_WEIGHTS.get(prob, 0) *
                IMPACT_WEIGHTS.get(imp, 0))

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
        """Textual recommendation based on the module and severity."""
        name = mod["name"]
        sev = mod["severity"]

        if "Rootkit" in name and sev in ("Critical", "High"):
            return ("Isolate the host from the network, analyze the filesystem, "
                    "and restore from a trusted backup if needed.")
        if ("Nmap" in name or "Ports" in name) and sev in ("High", "Medium"):
            return ("Close or filter unnecessary ports via firewall "
                    "(ufw/iptables) and verify exposed services.")
        if "Lynis" in name and sev in ("High", "Medium"):
            return ("Apply Lynis hardening recommendations, starting from "
                    "the highest-impact warnings.")
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

    # ------------------------------------------------------------------
    # Technical report
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Risk assessment
    # ------------------------------------------------------------------

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
                     "(Critical −40, High −20, Medium −10, Low −5, Info 0), "
                     "with floor at 0.")
        lines.append("")

        # --- Severity breakdown ---
        lines.append("## Severity Breakdown")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ("Critical", "High", "Medium", "Low", "OK", "Info"):
            lines.append(f"| {sev} | {counts[sev]} |")
        lines.append("")

        # --- Risk matrix ---
        lines.append("## Risk Matrix (Probability × Impact)")
        lines.append("")
        lines.append("> Risk Score = weight(Probability) × weight(Impact). "
                     "Weights: Low = 1, Medium = 2, High = 3, Critical = 4. ")
        lines.append("")
        lines.append("| Module | Severity | Probability | Impact | Risk Score | Priority |")
        lines.append("|--------|----------|-------------|--------|------------|----------|")
        for mod in self.modules:
            prob, imp = self._risk_for(mod)
            risk_score = self._risk_score(prob, imp)
            priority = self._priority_for(mod["severity"])
            lines.append(
                f"| {mod['name']} | {mod['severity']} | {prob} | {imp} "
                f"| {risk_score} | {priority} |"
            )
        lines.append("")

        # --- Top criticalities (sorted by risk score, then severity) ---
        urgent = [m for m in self.modules
                  if m["severity"] in ("Critical", "High", "Medium")]
        urgent.sort(
            key=lambda m: (
                self._risk_score(*self._risk_for(m)),
                SEVERITY_WEIGHTS.get(m["severity"], 0),
            ),
            reverse=True,
        )

        lines.append("## Top Criticalities")
        lines.append("")
        if not urgent:
            lines.append("No significant criticalities found. "
                         "The system appears to be in good condition.")
            lines.append("")
        else:
            for i, mod in enumerate(urgent, 1):
                prob, imp = self._risk_for(mod)
                risk_score = self._risk_score(prob, imp)
                lines.append(
                    f"### {i}. {mod['name']} — {mod['severity']} "
                    f"(Risk Score: {risk_score})"
                )
                lines.append("")
                lines.append(f"- **Probability:** {prob}")
                lines.append(f"- **Impact:** {imp}")
                lines.append(f"- **Risk Score:** {risk_score} / 16")
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
                     "(dangerous ports, Lynis warnings, rootkit keywords, "
                     "CVE counts, etc.).")
        lines.append("- **Probability**: estimated independently by each module "
                     "from its own findings (e.g. number of CVEs, warnings, "
                     "dangerous ports). When a module does not provide one, "
                     "it falls back to a severity-based default.")
        lines.append("- **Impact**: derived from the severity, unless the "
                     "module overrides it.")
        lines.append("- **Risk Score**: numeric value = weight(Probability) × "
                     "weight(Impact), with weights Low = 1, Medium = 2, "
                     "High = 3, Critical = 4. Range: 0–16.")
        lines.append("- **Security Score**: 100 − sum of severity weights, "
                     "with floor at 0.")
        lines.append("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Save
    # ------------------------------------------------------------------

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