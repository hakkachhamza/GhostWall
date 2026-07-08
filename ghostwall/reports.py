"""Report generation subsystem for GhostWall.

Supports HTML, JSON, CSV, and PDF output formats. Reports are written to the
configured reports directory and include the current security posture plus
provenance metadata.
"""

from __future__ import annotations

import csv
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ghostwall.core import SecurityModule

logger = logging.getLogger("ghostwall")


class ReportGenerator:
    """Generate security posture reports in multiple formats."""

    def __init__(
        self,
        app_name: str,
        app_version: str,
        hostname: str,
        report_dir: Path,
        log_path: Path,
        backup_path: Path,
    ) -> None:
        self.app_name = app_name
        self.app_version = app_version
        self.hostname = hostname
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = log_path
        self.backup_path = backup_path
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # ------------------------------------------------------------------
    # Shared posture collection
    # ------------------------------------------------------------------
    def _collect_posture(self, modules: List[SecurityModule]) -> Tuple[List[Dict[str, Any]], int, int]:
        rows: List[Dict[str, Any]] = []
        secure_count = 0
        for module in modules:
            try:
                verified = module.check()
            except Exception as exc:  # noqa: BLE001
                logger.error("Check failed for '%s' during report generation: %s", module.name, exc)
                verified = False
            secure_count += int(verified)
            rows.append(
                {
                    "name": module.name,
                    "description": module.description,
                    "framework_mapping": module.framework_mapping,
                    "framework_str": module.framework_str(),
                    "status": "SECURE" if verified else "VULNERABLE",
                    "verified": verified,
                    "destructive": module.destructive,
                }
            )
        return rows, secure_count, len(modules)

    # ------------------------------------------------------------------
    # HTML
    # ------------------------------------------------------------------
    def generate_html(self, modules: List[SecurityModule]) -> Path:
        """Generate an HTML report and return its path."""
        rows, secure_count, total = self._collect_posture(modules)
        score_pct = round(100 * secure_count / total) if total else 0

        rows_html = []
        for row in rows:
            status_class = "ok" if row["verified"] else "bad"
            status_text = row["status"]
            rows_html.append(
                f"<tr><td>{row['name']}</td><td>{row['description']}</td>"
                f"<td class='fw'>{row['framework_str']}</td>"
                f"<td><span class='{status_class}'>{status_text}</span></td></tr>"
            )

        css = "\n".join(
            [
                ":root { --bg:#0d1117; --panel:#161b22; --border:#30363d; "
                "--accent:#58a6ff; --ok:#3fb950; --bad:#f85149; --text:#c9d1d9; }",
                "* { box-sizing:border-box; }",
                "body { background:var(--bg); color:var(--text); "
                "font-family:'Segoe UI',system-ui,sans-serif; margin:0; padding:40px; }",
                ".wrap { max-width:1000px; margin:0 auto; }",
                "h1 { color:var(--accent); font-size:26px; margin-bottom:4px; }",
                ".meta { color:#8b949e; font-size:13px; margin-bottom:30px; }",
                ".score { display:inline-block; padding:18px 28px; border-radius:10px; "
                "background:var(--panel); border:1px solid var(--border); "
                "font-size:22px; font-weight:700; margin-bottom:28px; }",
                "table { width:100%; border-collapse:collapse; background:var(--panel); "
                "border:1px solid var(--border); border-radius:8px; overflow:hidden; }",
                "th, td { text-align:left; padding:12px 16px; "
                "border-bottom:1px solid var(--border); font-size:13px; }",
                "th { background:#1c2129; color:var(--accent); text-transform:uppercase; "
                "font-size:11px; letter-spacing:.05em; }",
                "tr:last-child td { border-bottom:none; }",
                ".ok { color:var(--ok); font-weight:700; }",
                ".bad { color:var(--bad); font-weight:700; }",
                ".fw { color:#8b949e; font-size:11px; }",
                "footer { margin-top:24px; font-size:12px; color:#8b949e; }",
            ]
        )
        generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>{self.app_name} - Report</title>
<style>
{css}
</style></head><body><div class="wrap">
<h1>{self.app_name} v{self.app_version}</h1>
<div class="meta">Host: {self.hostname} &nbsp;|&nbsp; Generated {generated}</div>
<div class="score">Security Score: {secure_count}/{total} controls verified secure ({score_pct}%)</div>
<table><thead><tr><th>Control</th><th>Description</th><th>Framework Mapping</th><th>Status</th></tr></thead>
<tbody>{''.join(rows_html)}</tbody></table>
<footer>SIEM-ready log: {self.log_path} &nbsp;|&nbsp; Rollback backup: {self.backup_path}</footer>
</div></body></html>"""
        path = self.report_dir / f"ghostwall_report_{self.timestamp}.html"
        path.write_text(html, encoding="utf-8")
        logger.info("HTML report saved to %s", path)
        return path

    # ------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------
    def generate_json(self, modules: List[SecurityModule]) -> Path:
        """Generate a JSON report and return its path."""
        rows, secure_count, total = self._collect_posture(modules)
        score_pct = round(100 * secure_count / total) if total else 0
        payload = {
            "app_name": self.app_name,
            "app_version": self.app_version,
            "hostname": self.hostname,
            "generated_at": datetime.now().isoformat(),
            "score": {
                "secure": secure_count,
                "total": total,
                "percentage": score_pct,
            },
            "controls": rows,
            "provenance": {
                "log_path": str(self.log_path),
                "backup_path": str(self.backup_path),
            },
        }
        path = self.report_dir / f"ghostwall_report_{self.timestamp}.json"
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        logger.info("JSON report saved to %s", path)
        return path

    # ------------------------------------------------------------------
    # CSV
    # ------------------------------------------------------------------
    def generate_csv(self, modules: List[SecurityModule]) -> Path:
        """Generate a CSV report and return its path."""
        rows, secure_count, total = self._collect_posture(modules)
        path = self.report_dir / f"ghostwall_report_{self.timestamp}.csv"
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(
                fh,
                fieldnames=["name", "description", "framework_cis", "framework_mitre", "framework_nist", "status"],
            )
            writer.writeheader()
            for row in rows:
                writer.writerow(
                    {
                        "name": row["name"],
                        "description": row["description"],
                        "framework_cis": ", ".join(row["framework_mapping"].get("cis", [])),
                        "framework_mitre": ", ".join(row["framework_mapping"].get("mitre", [])),
                        "framework_nist": ", ".join(row["framework_mapping"].get("nist", [])),
                        "status": row["status"],
                    }
                )
            writer.writerow(
                {
                    "name": "SCORE",
                    "description": (
                        f"{secure_count}/{total} secure " f"({round(100 * secure_count / total) if total else 0}%)"
                    ),
                    "framework_cis": "",
                    "framework_mitre": "",
                    "framework_nist": "",
                    "status": "",
                }
            )
        logger.info("CSV report saved to %s", path)
        return path

    # ------------------------------------------------------------------
    # PDF
    # ------------------------------------------------------------------
    def generate_pdf(self, modules: List[SecurityModule]) -> Path:
        """Generate a PDF report and return its path.

        Uses ``fpdf`` or ``reportlab`` if available; otherwise renders the HTML
        report and logs a warning explaining the missing optional dependency.
        """
        path = self.report_dir / f"ghostwall_report_{self.timestamp}.pdf"
        rows, secure_count, total = self._collect_posture(modules)
        score_pct = round(100 * secure_count / total) if total else 0

        pdf_backend = self._choose_pdf_backend()
        if pdf_backend == "fpdf":
            self._generate_pdf_fpdf(path, rows, secure_count, total, score_pct)
        elif pdf_backend == "reportlab":
            self._generate_pdf_reportlab(path, rows, secure_count, total, score_pct)
        else:
            html_path = self.generate_html(modules)
            logger.warning("PDF generation requires 'fpdf' or 'reportlab'. HTML report written to %s", html_path)
            raise RuntimeError(
                "PDF generation requires 'fpdf' or 'reportlab'. " "Install one of them, or use --report-format html."
            )
        logger.info("PDF report saved to %s", path)
        return path

    @staticmethod
    def _choose_pdf_backend() -> Optional[str]:
        try:
            import fpdf  # noqa: F401

            return "fpdf"
        except ImportError:
            pass
        try:
            import reportlab  # noqa: F401

            return "reportlab"
        except ImportError:
            pass
        return None

    def _generate_pdf_fpdf(
        self,
        path: Path,
        rows: List[Dict[str, Any]],
        secure_count: int,
        total: int,
        score_pct: int,
    ) -> None:
        from fpdf import FPDF

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, f"{self.app_name} v{self.app_version}", ln=True)
        pdf.set_font("Arial", "", 10)
        pdf.cell(0, 6, f"Host: {self.hostname} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
        pdf.ln(4)
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 8, f"Security Score: {secure_count}/{total} ({score_pct}%)", ln=True)
        pdf.ln(4)

        for row in rows:
            pdf.set_font("Arial", "B", 10)
            pdf.cell(0, 6, row["name"], ln=True)
            pdf.set_font("Arial", "", 9)
            pdf.multi_cell(0, 5, f"Description: {row['description']}")
            pdf.multi_cell(0, 5, f"Framework: {row['framework_str']}")
            pdf.multi_cell(0, 5, f"Status: {row['status']}")
            pdf.ln(2)

        pdf.output(str(path))

    def _generate_pdf_reportlab(
        self,
        path: Path,
        rows: List[Dict[str, Any]],
        secure_count: int,
        total: int,
        score_pct: int,
    ) -> None:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet

        doc = SimpleDocTemplate(str(path), pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        story.append(Paragraph(f"<b>{self.app_name} v{self.app_version}</b>", styles["Title"]))
        story.append(
            Paragraph(
                f"Host: {self.hostname} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                styles["Normal"],
            )
        )
        story.append(Spacer(1, 12))
        story.append(
            Paragraph(
                f"<b>Security Score:</b> {secure_count}/{total} ({score_pct}%)",
                styles["Heading2"],
            )
        )
        story.append(Spacer(1, 12))

        table_data = [["Control", "Description", "Framework", "Status"]]
        for row in rows:
            table_data.append(
                [
                    row["name"],
                    row["description"],
                    row["framework_str"],
                    row["status"],
                ]
            )
        table = Table(table_data, colWidths=[120, 180, 150, 60])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1c2129")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#58a6ff")),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#161b22")),
                    ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#c9d1d9")),
                    ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#30363d")),
                    ("FONTSIZE", (0, 1), (-1, -1), 8),
                ]
            )
        )
        story.append(table)
        doc.build(story)
