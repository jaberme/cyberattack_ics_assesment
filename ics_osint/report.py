"""Fase 7 — Documentación: informe Markdown y exportaciones CSV.

Genera un informe reproducible con las tablas que alimentan el capítulo 5 del
TFG. Todas las direcciones IP se emiten anonimizadas y no se incluyen nombres
de organización, conforme al principio de anonimización (Sección 3.1.3).
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .anonymize import anonymize_record


def _fmt(v: Any) -> str:
    if v is None:
        return "—"
    if isinstance(v, bool):
        return "Sí" if v else "No"
    return str(v)


def write_markdown(
    summary: dict,
    sev_dist: dict,
    top_cves: list[dict],
    out_path: str | Path,
    title: str = "Informe de exposición ICS/OT (OSINT pasivo)",
) -> Path:
    """Escribe el informe principal en Markdown."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines: list[str] = []
    lines.append(f"# {title}\n")
    lines.append(
        f"_Generado automáticamente el {now} mediante consulta pasiva del índice "
        f"de Censys. Direcciones IP anonimizadas; organizaciones omitidas._\n"
    )

    # --- Resumen global ---
    lines.append("## Visión global de la exposición\n")
    lines.append(f"- **Hosts ICS/OT identificados:** {summary['total_hosts']}\n")
    lines.append("### Exposición por región\n")
    lines.append("| Región | Hosts | Protocolo dominante | Acceso remoto expuesto |")
    lines.append("|---|---:|---|---|")
    for r in summary["by_region"]:
        exp = ", ".join(f"{k}: {v}" for k, v in r["exposure"].items()) or "—"
        lines.append(
            f"| {r['region']} | {r['hosts']} | {r['dominant_protocol']} | {exp} |"
        )
    lines.append("")

    # --- Distribución de protocolos ---
    lines.append("### Distribución de protocolos\n")
    lines.append("| Protocolo | Hosts | % |")
    lines.append("|---|---:|---:|")
    for p in summary["protocol_distribution"]:
        lines.append(f"| {p['protocol']} | {p['count']} | {p['pct']} % |")
    lines.append("")

    # --- Servicios de acceso remoto ---
    if summary.get("exposure_counts"):
        lines.append("### Servicios de acceso remoto expuestos (global)\n")
        lines.append("| Servicio | Hosts |")
        lines.append("|---|---:|")
        for k, v in summary["exposure_counts"].items():
            lines.append(f"| {k} | {v} |")
        lines.append("")

    # --- Severidad ---
    if sev_dist:
        lines.append("### Distribución de severidad de hallazgos\n")
        lines.append("| Nivel | Hallazgos |")
        lines.append("|---|---:|")
        for level in ("CRÍTICO", "ALTO", "MEDIO", "BAJO"):
            if level in sev_dist:
                lines.append(f"| {level} | {sev_dist[level]} |")
        lines.append("")

    # --- Top CVEs ---
    if top_cves:
        lines.append("### CVEs potencialmente aplicables más frecuentes\n")
        lines.append(
            "_Correlación potencial basada en el fingerprint indexado; no implica "
            "explotación confirmada._\n"
        )
        lines.append("| CVE | Hosts | CVSS | KEV | Descripción |")
        lines.append("|---|---:|---:|:---:|---|")
        for c in top_cves:
            lines.append(
                f"| {c['id']} | {c['hosts']} | {_fmt(c.get('cvss'))} | "
                f"{_fmt(c.get('in_kev'))} | {(c.get('description') or '')[:80]} |"
            )
        lines.append("")

    out_path.write_text("\n".join(lines), encoding="utf-8")
    return out_path


def write_findings_csv(
    findings: list[dict],
    out_path: str | Path,
    anon_method: str = "truncate",
    keep_octets: int = 2,
    salt: str = "",
    omit_org: bool = True,
) -> Path:
    """Exporta los hallazgos a CSV con IPs anonimizadas."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    cols = ["ip", "country_code", "severity", "max_cvss", "in_kev", "ports", "cve_ids"]
    with out_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(cols)
        for f in findings:
            anon = anonymize_record(f, anon_method, keep_octets, salt, omit_org)
            writer.writerow(
                [
                    anon.get("ip", ""),
                    anon.get("country_code", ""),
                    anon.get("severity", ""),
                    anon.get("max_cvss", ""),
                    anon.get("in_kev", ""),
                    " ".join(str(p) for p in anon.get("ports", [])),
                    " ".join(c.get("id", "") for c in anon.get("cves", [])),
                ]
            )
    return out_path


def write_counts_csv(counts: list[dict], out_path: str | Path) -> Path:
    """Exporta los contadores por consulta (Apéndice A reproducible)."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["query_id", "region", "description", "total", "retrieved"])
        for c in counts:
            writer.writerow(
                [
                    c.get("id", ""),
                    c.get("region", ""),
                    c.get("description", ""),
                    c.get("total", ""),
                    c.get("retrieved", ""),
                ]
            )
    return out_path
