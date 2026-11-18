import io
import re
import csv
import json
from typing import List, Any
from datetime import datetime
from app.models.scan import Scan
from app.models.target import Target
from app.models.finding import Finding

def escape_pdf_text(text: str) -> str:
    """Escapes characters for PDF literal strings."""
    if not text:
        return ""
    # Remove characters outside standard printable ascii / latin-1
    clean = re.sub(r'[^\x20-\x7E]', ' ', str(text))
    return clean.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')

class PurePDFGenerator:
    """
    Self-contained, pure-Python PDF 1.4 generator.
    Produces high-fidelity, valid PDF documents without external C/pip dependencies.
    """
    def __init__(self):
        self.objects = []
        self.pages = []
        self.current_stream = []
        self.y = 800  # Start near top of A4 (595 x 842 pt)
        self.page_width = 595
        self.page_height = 842
        self.margin_x = 40
        self.margin_bottom = 50

    def _start_page(self):
        self.current_stream = []
        self.y = 790

    def _end_page(self):
        stream_content = "\n".join(self.current_stream)
        stream_bytes = stream_content.encode("latin-1", errors="replace")
        self.pages.append(stream_bytes)

    def new_page_if_needed(self, required_space: int = 50):
        if self.y - required_space < self.margin_bottom:
            self._end_page()
            self._start_page()

    def add_rect(self, x: float, y: float, w: float, h: float, r: float, g: float, b: float, fill: bool = True):
        cmd = f"{r:.2f} {g:.2f} {b:.2f} rg\n{x:.1f} {y:.1f} {w:.1f} {h:.1f} re f" if fill else f"{r:.2f} {g:.2f} {b:.2f} RG\n{x:.1f} {y:.1f} {w:.1f} {h:.1f} re s"
        self.current_stream.append(cmd)

    def add_text(self, text: str, x: float, y: float, size: int = 10, bold: bool = False, r: float = 0.1, g: float = 0.1, b: float = 0.1):
        font = "/F2" if bold else "/F1"
        safe_str = escape_pdf_text(text)
        self.current_stream.append(f"BT\n{font} {size} Tf\n{r:.2f} {g:.2f} {b:.2f} rg\n{x:.1f} {y:.1f} Td\n({safe_str}) Tj\nET")

    def add_line(self, x1: float, y1: float, x2: float, y2: float, r: float = 0.8, g: float = 0.8, b: float = 0.8):
        self.current_stream.append(f"{r:.2f} {g:.2f} {b:.2f} RG\n1 w\n{x1:.1f} {y1:.1f} m\n{x2:.1f} {y2:.1f} l S")

    def build_bytes(self) -> bytes:
        if self.current_stream:
            self._end_page()

        # Build PDF Object Structure
        # 1: Catalog, 2: Pages, 3: Font Regular, 4: Font Bold
        # 5..(5+2N): Page and Content Streams
        pdf = bytearray()
        pdf.extend(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        
        offsets = {}
        obj_count = 0

        def write_obj(content: bytes) -> int:
            nonlocal obj_count
            obj_count += 1
            offsets[obj_count] = len(pdf)
            pdf.extend(f"{obj_count} 0 obj\n".encode("ascii"))
            pdf.extend(content)
            pdf.extend(b"\nendobj\n")
            return obj_count

        catalog_id = 1
        pages_id = 2
        font_reg_id = 3
        font_bold_id = 4

        # Reserve first 4 objects
        obj_count = 4

        page_obj_ids = []
        content_obj_ids = []

        for p_bytes in self.pages:
            c_id = write_obj(f"<< /Length {len(p_bytes)} >>\nstream\n".encode("ascii") + p_bytes + b"\nendstream")
            content_obj_ids.append(c_id)

            p_id = write_obj(
                f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 {self.page_width} {self.page_height}] "
                f"/Contents {c_id} 0 R /Resources << /Font << /F1 {font_reg_id} 0 R /F2 {font_bold_id} 0 R >> >> >>".encode("ascii")
            )
            page_obj_ids.append(p_id)

        # Write Fonts
        offsets[font_reg_id] = len(pdf)
        pdf.extend(f"{font_reg_id} 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n".encode("ascii"))

        offsets[font_bold_id] = len(pdf)
        pdf.extend(f"{font_bold_id} 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n".encode("ascii"))

        # Write Pages Tree
        kids_str = " ".join(f"{pid} 0 R" for pid in page_obj_ids)
        offsets[pages_id] = len(pdf)
        pdf.extend(f"{pages_id} 0 obj\n<< /Type /Pages /Kids [{kids_str}] /Count {len(page_obj_ids)} >>\nendobj\n".encode("ascii"))

        # Write Catalog
        offsets[catalog_id] = len(pdf)
        pdf.extend(f"{catalog_id} 0 obj\n<< /Type /Catalog /Pages {pages_id} 0 R >>\nendobj\n".encode("ascii"))

        # Cross Reference Table
        xref_offset = len(pdf)
        pdf.extend(f"xref\n0 {obj_count + 1}\n0000000000 65535 f \n".encode("ascii"))
        for i in range(1, obj_count + 1):
            pdf.extend(f"{offsets[i]:010d} 00000 n \n".encode("ascii"))

        pdf.extend(f"trailer\n<< /Size {obj_count + 1} /Root {catalog_id} 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("ascii"))
        return bytes(pdf)


class ReportGenerator:
    """
    Section 6 Downloadable Reports Service:
    Generates standard vulnerability reports in JSON, SARIF 2.1.0, CSV, and Professional PDF formats.
    """

    @classmethod
    def generate_json_report(cls, scan: Scan, target: Target, findings: List[Finding]) -> str:
        report = {
            "aegisai_report_version": "1.0",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "organization": "Provilance Technologies",
            "scan_metadata": {
                "scan_id": scan.id,
                "profile": scan.profile,
                "tiers": json.loads(scan.tiers) if isinstance(scan.tiers, str) else scan.tiers,
                "status": scan.status,
                "target_url": target.url,
                "target_domain": target.domain,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
                "duration_seconds": scan.duration,
                "total_findings": len(findings)
            },
            "findings": [
                {
                    "id": f.id,
                    "tool": f.tool,
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "category": f.category,
                    "cwe": f.cwe,
                    "cve": json.loads(f.cve) if isinstance(f.cve, str) else f.cve,
                    "cvss": f.cvss,
                    "epss": f.epss,
                    "kev": f.kev,
                    "url": f.url,
                    "host": f.host,
                    "port": f.port,
                    "parameter": f.parameter,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "references": json.loads(f.references) if isinstance(f.references, str) else f.references,
                    "fingerprint_hash": f.fingerprint_hash
                }
                for f in findings
            ]
        }
        return json.dumps(report, indent=2)

    @classmethod
    def generate_sarif_report(cls, scan: Scan, target: Target, findings: List[Finding]) -> str:
        sarif_results = []
        rules_map = {}

        for f in findings:
            if f.rule_id not in rules_map:
                rules_map[f.rule_id] = {
                    "id": f.rule_id,
                    "name": f.title,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description},
                    "help": {"text": f.remediation},
                    "properties": {
                        "category": f.category,
                        "cwe": f.cwe,
                        "cvss": f.cvss,
                        "security-severity": str(f.cvss)
                    }
                }

            level = "error" if f.severity in ["critical", "high"] else ("warning" if f.severity == "medium" else "note")

            sarif_results.append({
                "ruleId": f.rule_id,
                "level": level,
                "message": {"text": f"{f.title}: {f.description}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.url}}}],
                "properties": {
                    "confidence": f.confidence,
                    "evidence": f.evidence,
                    "cvss": f.cvss,
                    "epss": f.epss,
                    "kev": f.kev,
                    "remediation": f.remediation
                }
            })

        sarif_payload = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "AegisAI Vulnerability Scanner",
                            "version": "1.0.0",
                            "informationUri": "https://provilance.com/aegisai",
                            "rules": list(rules_map.values())
                        }
                    },
                    "results": sarif_results
                }
            ]
        }
        return json.dumps(sarif_payload, indent=2)

    @classmethod
    def generate_csv_report(cls, scan: Scan, target: Target, findings: List[Finding]) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Finding ID", "Severity", "Confidence", "Title", "Category",
            "CWE", "CVSS", "EPSS", "CISA KEV", "URL", "Tool", "Rule ID",
            "Remediation", "Evidence Excerpt"
        ])
        for f in findings:
            writer.writerow([
                f.id, f.severity.upper(), f.confidence, f.title, f.category,
                f.cwe, f.cvss, f.epss, "YES" if f.kev else "NO", f.url,
                f.tool, f.rule_id, f.remediation,
                f.evidence[:300].replace("\n", " ") if f.evidence else ""
            ])
        return output.getvalue()

    @classmethod
    def generate_pdf_report(cls, scan: Scan, target: Target, findings: List[Finding]) -> bytes:
        """
        Generates an executive, publication-grade PDF report.
        Includes Provilance Technologies branding, executive summary, and findings tables.
        """
        pdf = PurePDFGenerator()
        pdf._start_page()

        # 1. Header Banner
        pdf.add_rect(0, 780, 595, 62, 0.05, 0.1, 0.18)
        pdf.add_text("AEGISAI SECURITY ASSESSMENT REPORT", 40, 810, size=15, bold=True, r=0.2, g=0.8, b=0.95)
        pdf.add_text("PROVILANCE TECHNOLOGIES | DETECTION-ONLY SAAS", 40, 792, size=9, bold=False, r=0.7, g=0.75, b=0.8)

        # 2. Target & Metadata Box
        pdf.y = 750
        pdf.add_rect(40, 680, 515, 65, 0.96, 0.97, 0.99)
        pdf.add_line(40, 745, 555, 745, 0.85, 0.88, 0.92)
        pdf.add_line(40, 680, 555, 680, 0.85, 0.88, 0.92)

        pdf.add_text("Target Website:", 55, 725, size=9, bold=True, r=0.2, g=0.3, b=0.4)
        pdf.add_text(target.url[:60], 140, 725, size=9, bold=False)

        pdf.add_text("Domain / Host:", 55, 708, size=9, bold=True, r=0.2, g=0.3, b=0.4)
        pdf.add_text(target.domain, 140, 708, size=9, bold=False)

        pdf.add_text("Profile:", 330, 725, size=9, bold=True, r=0.2, g=0.3, b=0.4)
        pdf.add_text(scan.profile.upper(), 390, 725, size=9, bold=True, r=0.1, g=0.6, b=0.8)

        pdf.add_text("Duration:", 330, 708, size=9, bold=True, r=0.2, g=0.3, b=0.4)
        pdf.add_text(f"{scan.duration or 0.0}s", 390, 708, size=9, bold=False)

        pdf.add_text("Generated At:", 55, 691, size=9, bold=True, r=0.2, g=0.3, b=0.4)
        pdf.add_text(datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"), 140, 691, size=9, bold=False)

        # 3. Executive Metrics Overview
        pdf.y = 650
        pdf.add_text("Executive Threat & Posture Summary", 40, 655, size=12, bold=True, r=0.1, g=0.15, b=0.25)

        # Severity Counts
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        cisa_kev_count = 0
        for f in findings:
            s = (f.severity or "info").lower()
            sev_counts[s] = sev_counts.get(s, 0) + 1
            if getattr(f, "kev", False):
                cisa_kev_count += 1

        # Summary Badges
        # Critical
        pdf.add_rect(40, 600, 115, 42, 0.95, 0.9, 0.9)
        pdf.add_text(f"{sev_counts['critical']} CRITICAL", 52, 622, size=11, bold=True, r=0.8, g=0.1, b=0.1)
        pdf.add_text("Immediate action", 52, 608, size=8, bold=False, r=0.5, g=0.2, b=0.2)

        # High
        pdf.add_rect(170, 600, 115, 42, 0.98, 0.94, 0.9)
        pdf.add_text(f"{sev_counts['high']} HIGH", 185, 622, size=11, bold=True, r=0.85, g=0.4, b=0.1)
        pdf.add_text("Elevated exposure", 185, 608, size=8, bold=False, r=0.5, g=0.3, b=0.1)

        # Medium
        pdf.add_rect(300, 600, 115, 42, 0.98, 0.97, 0.88)
        pdf.add_text(f"{sev_counts['medium']} MEDIUM", 312, 622, size=11, bold=True, r=0.7, g=0.55, b=0.1)
        pdf.add_text("Hardening required", 312, 608, size=8, bold=False, r=0.5, g=0.4, b=0.1)

        # Low & Info
        pdf.add_rect(430, 600, 125, 42, 0.92, 0.95, 0.98)
        pdf.add_text(f"{sev_counts['low'] + sev_counts['info']} LOW / INFO", 442, 622, size=11, bold=True, r=0.2, g=0.4, b=0.8)
        pdf.add_text("Best practice notes", 442, 608, size=8, bold=False, r=0.3, g=0.4, b=0.6)

        # 4. Detailed Findings Listing
        pdf.y = 570
        pdf.add_text("Vulnerability Findings & Corroborated Evidence", 40, 570, size=12, bold=True, r=0.1, g=0.15, b=0.25)
        pdf.add_line(40, 560, 555, 560, 0.8, 0.85, 0.9)

        pdf.y = 540

        if not findings:
            pdf.add_rect(40, 480, 515, 50, 0.92, 0.98, 0.94)
            pdf.add_text("Clean Security Posture: No Vulnerabilities Detected", 130, 505, size=11, bold=True, r=0.1, g=0.6, b=0.3)
            pdf.add_text("All passive and active baseline security tests passed safely.", 130, 492, size=9, bold=False, r=0.3, g=0.5, b=0.4)
        else:
            for i, f in enumerate(findings):
                pdf.new_page_if_needed(120)

                # Severity Color Tag
                sev_color = {
                    "critical": (0.8, 0.15, 0.15),
                    "high": (0.9, 0.45, 0.1),
                    "medium": (0.75, 0.6, 0.1),
                    "low": (0.2, 0.5, 0.8),
                    "info": (0.5, 0.5, 0.5)
                }.get((f.severity or "info").lower(), (0.4, 0.4, 0.4))

                card_y = pdf.y - 100
                pdf.add_rect(40, card_y, 515, 95, 0.98, 0.98, 0.99)
                pdf.add_rect(40, card_y, 4, 95, *sev_color)

                # Title & Severity
                pdf.add_text(f"#{i+1} [{f.severity.upper()}] {f.title[:65]}", 52, card_y + 78, size=10, bold=True, r=0.1, g=0.1, b=0.15)
                
                # Badges
                kev_label = " | CISA KEV ACTIVE" if f.kev else ""
                cvss_str = f"CVSS: {f.cvss or 0.0} | EPSS: {f.epss or 0.0}{kev_label}"
                pdf.add_text(cvss_str, 390, card_y + 78, size=8, bold=True, r=0.8 if f.kev else 0.3, g=0.1 if f.kev else 0.3, b=0.1 if f.kev else 0.4)

                # Description
                pdf.add_text(f.description[:95] if f.description else "", 52, card_y + 60, size=8, bold=False, r=0.3, g=0.3, b=0.3)

                # Evidence & Location
                pdf.add_text(f"Location: {f.url[:70]}", 52, card_y + 44, size=8, bold=False, r=0.2, g=0.4, b=0.6)
                pdf.add_text(f"Evidence: {f.evidence[:85]}", 52, card_y + 30, size=8, bold=False, r=0.4, g=0.4, b=0.4)

                # Remediation
                pdf.add_text(f"Remediation: {f.remediation[:88]}", 52, card_y + 14, size=8, bold=True, r=0.1, g=0.5, b=0.3)

                pdf.y = card_y - 12

        return pdf.build_bytes()
