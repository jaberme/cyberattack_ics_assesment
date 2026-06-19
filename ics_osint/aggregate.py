"""Fase 6 — Agregación estadística (visión global de la exposición).

Recrea, a partir de los hosts depurados, la base cuantitativa del capítulo 5
del TFG: número de hosts por región, protocolo dominante, distribución de
protocolos, recuentos de servicios de acceso remoto expuestos (VNC, Telnet,
CODESYS, RDP) y distribución de severidad.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from .fingerprint import PORT_PROTOCOL, host_country, host_ports

# Puertos -> etiqueta de exposición destacada en el TFG.
EXPOSURE_PORTS = {
    5900: "VNC",
    23: "Telnet",
    1217: "CODESYS",
    3389: "RDP",
    34964: "PROFINET-CM",
}


def country_to_region(code: str | None, mapping: dict[str, str]) -> str:
    if not code:
        return "Desconocida"
    return mapping.get(code.upper(), "Otras")


def dominant_protocol(port_counter: Counter) -> str:
    """Protocolo dominante a partir del recuento de puertos."""
    if not port_counter:
        return "—"
    port, _ = port_counter.most_common(1)[0]
    return PORT_PROTOCOL.get(port, f"puerto {port}")


def summarize(hosts: list[dict], regions: dict[str, str]) -> dict:
    """Genera el resumen global de exposición."""
    total = len(hosts)
    by_region_hosts: dict[str, int] = defaultdict(int)
    by_region_ports: dict[str, Counter] = defaultdict(Counter)
    global_ports: Counter = Counter()
    exposure_counts: dict[str, int] = defaultdict(int)
    exposure_by_region: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for host in hosts:
        region = country_to_region(host_country(host), regions)
        ports = host_ports(host)
        by_region_hosts[region] += 1
        for p in ports:
            by_region_ports[region][p] += 1
            global_ports[p] += 1
            if p in EXPOSURE_PORTS:
                exposure_counts[EXPOSURE_PORTS[p]] += 1
                exposure_by_region[region][EXPOSURE_PORTS[p]] += 1

    # Distribución de protocolos (porcentaje sobre puertos ICS conocidos).
    known = Counter()
    for p, c in global_ports.items():
        if p in PORT_PROTOCOL:
            known[PORT_PROTOCOL[p]] += c
    total_known = sum(known.values()) or 1
    protocol_distribution = [
        {
            "protocol": proto,
            "count": cnt,
            "pct": round(100 * cnt / total_known, 1),
        }
        for proto, cnt in known.most_common()
    ]

    region_summary = []
    for region, n in sorted(by_region_hosts.items(), key=lambda kv: -kv[1]):
        region_summary.append(
            {
                "region": region,
                "hosts": n,
                "dominant_protocol": dominant_protocol(by_region_ports[region]),
                "exposure": dict(exposure_by_region[region]),
            }
        )

    return {
        "total_hosts": total,
        "by_region": region_summary,
        "protocol_distribution": protocol_distribution,
        "exposure_counts": dict(exposure_counts),
    }


def severity_distribution(findings: list[dict]) -> dict[str, int]:
    """Distribución de severidad sobre los hallazgos analizados."""
    counter = Counter(f.get("severity", "BAJO") for f in findings)
    return dict(counter)


def top_cves(findings: list[dict], limit: int = 15) -> list[dict]:
    """CVEs más frecuentes entre los hallazgos (para la sección de resultados)."""
    counter: Counter = Counter()
    detail: dict[str, dict] = {}
    for f in findings:
        for cve in f.get("cves", []):
            cid = cve.get("id")
            if not cid:
                continue
            counter[cid] += 1
            detail.setdefault(cid, cve)
    out = []
    for cid, cnt in counter.most_common(limit):
        d = detail[cid]
        out.append(
            {
                "id": cid,
                "hosts": cnt,
                "cvss": d.get("cvss"),
                "in_kev": d.get("in_kev", False),
                "description": d.get("description", ""),
            }
        )
    return out
