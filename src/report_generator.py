# src/report_generator.py
from typing import List
from scanner import Finding


class ReportGenerator:
    def __init__(self, findings: List[Finding]):
        self.findings = findings

    def overall_risk_score(self) -> int:
        weights = {"BAIXA": 1, "MÉDIA": 2, "ALTA": 3, "CRÍTICA": 4}
        if not self.findings:
            return 0
        total = sum(weights.get(f.severity, 2) for f in self.findings)
        return round((total / (len(self.findings) * 4)) * 100)

    def to_markdown(self) -> str:
        score = self.overall_risk_score()
        md = []
        md.append(f"# Relatório de Segurança – TechHacker Scanner\n")
        md.append(f"**Score de Risco Global:** {score}/100\n")
        md.append("## Resumo das Vulnerabilidades\n")

        for f in self.findings:
            md.append(f"### {f.vuln_type} ({f.severity})\n")
            md.append(f"- **URL:** `{f.endpoint}`\n")
            md.append(f"- **Parâmetro:** `{f.param}`\n")
            md.append(f"- **Evidência:** {f.evidence}\n")
            md.append(f"- **Recomendação:** {f.recommendation}\n")
            md.append(f"- **Metodologia:** {f.methodology}\n")
            md.append("---\n")

        return "\n".join(md)
