"""
modules/report_builder.py — Report Builder Module.

Exports findings to Markdown, JSON, and HTML using Jinja2 templates.
Supports IP anonymisation (substitution with host-A, host-B labels).
"""

import os
import json
import dataclasses
from collections import defaultdict
from typing import List

from jinja2 import Environment, FileSystemLoader

from modules import Finding


MODULE_NUM  = 13
MODULE_NAME = "Report Builder"
MODULE_ID   = "report"


# ──────────────────────────────────────────────────────
# IP anonymisation
# ──────────────────────────────────────────────────────
_ANONYMIZE_MAP = {}
_ANON_COUNTER = 65  # 65 = 'A'

def _anonymize_ip(ip_str: str) -> str:
    global _ANON_COUNTER
    if ip_str not in _ANONYMIZE_MAP:
        _ANONYMIZE_MAP[ip_str] = f"host-{chr(_ANON_COUNTER)}"
        _ANON_COUNTER += 1
        if _ANON_COUNTER > 90:  # Z
            _ANON_COUNTER = 65
    return _ANONYMIZE_MAP[ip_str]

def anonymize_findings(findings: List[Finding]) -> List[Finding]:
    """Replaces IP addresses in findings when anonymisation is requested."""
    import re
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    anonymized = []
    for f in findings:
        f_copy = dataclasses.replace(f)

        # Find all IPs in description and evidence
        ips = set(ip_pattern.findall(f_copy.descripcion) + ip_pattern.findall(f_copy.evidencia))

        for ip in ips:
            anon = _anonymize_ip(ip)
            f_copy.descripcion = f_copy.descripcion.replace(ip, anon)
            f_copy.evidencia   = f_copy.evidencia.replace(ip, anon)
            f_copy.titulo      = f_copy.titulo.replace(ip, anon)

        anonymized.append(f_copy)

    return anonymized


# ──────────────────────────────────────────────────────
# Exporters
# ──────────────────────────────────────────────────────
def get_jinja_env():
    """Configures and returns the Jinja2 environment."""
    template_dir = os.path.join(os.path.dirname(__file__), "..", "templates")
    os.makedirs(template_dir, exist_ok=True)
    return Environment(loader=FileSystemLoader(template_dir))


def export_markdown(findings: List[Finding], capture_info: dict, out_path: str):
    env = get_jinja_env()
    try:
        template = env.get_template("report.md.j2")
    except Exception:
        # Fallback if template is missing
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(f"# LookingTheShark Report\n\n**Capture**: {capture_info.get('nombre')}\n\n")
            for fd in findings:
                f.write(f"### [{fd.severidad.upper()}] {fd.titulo}\n")
                f.write(f"- **Description**: {fd.descripcion}\n")
                f.write(f"- **Evidence**: {fd.evidencia}\n")
                if fd.mitre_name:
                    f.write(f"- **MITRE**: {fd.mitre_name}\n")
                f.write("\n")
        return

    content = template.render(
        findings=findings,
        capture=capture_info,
    )
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(content)


def export_html(findings: List[Finding], capture_info: dict, out_path: str):
    env = get_jinja_env()
    try:
        template = env.get_template("report.html.j2")
    except Exception:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(f"<html><body><h1>LookingTheShark Report</h1><p>Capture: {capture_info.get('nombre')}</p></body></html>")
        return

    content = template.render(
        findings=findings,
        capture=capture_info,
    )
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(content)


def export_json(findings: List[Finding], capture_info: dict, out_path: str):
    data = {
        "metadata": {
            "tool": "LookingTheShark",
            "version": "1.0",
            "capture_file": capture_info.get("nombre", ""),
            "packets": capture_info.get("paquetes", 0),
        },
        "findings": [dataclasses.asdict(f) for f in findings]
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


def build_reports(findings: List[Finding], config: dict, capture_info: dict) -> None:
    """Generates all reports requested by the user."""

    # Anonymise if requested
    if config.get("anonymize", False):
        findings_to_export = anonymize_findings(findings)
    else:
        findings_to_export = findings

    # Sort findings by severity for the templates
    findings_to_export.sort(
        key=lambda x: {"critico": 0, "alto": 1, "medio": 2, "bajo": 3, "info": 4}.get(x.severidad, 5)
    )

    fmt = config.get("format", "md").lower()
    base_name = config.get("output_base", "report_capture")

    if "md" in fmt:
        path = f"{base_name}.md"
        export_markdown(findings_to_export, capture_info, path)
        print(f"[+] Markdown report generated: {path}")

    if "html" in fmt:
        path = f"{base_name}.html"
        export_html(findings_to_export, capture_info, path)
        print(f"[+] HTML report generated: {path}")

    if "json" in fmt:
        path = f"{base_name}.json"
        export_json(findings_to_export, capture_info, path)
        print(f"[+] JSON report generated: {path}")
