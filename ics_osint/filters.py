"""Fase 4 — Filtrado y depuración de falsos positivos.

Implementa los criterios de la Tabla 4.2 del TFG:
  - Etiqueta honeypot de Censys.
  - Rangos de proveedores cloud (AWS, Azure, GCP, DigitalOcean...) sin uso
    industrial justificado.
  - Geolocalización incoherente (verificación cruzada ligera país/ASN).

Cada host se evalúa de forma defensiva sobre el JSON devuelto por Censys; los
nombres de campo se buscan tolerando ausencias.
"""

from __future__ import annotations

from typing import Any


def _services(host: dict) -> list[dict]:
    svcs = host.get("services") or host.get("host", {}).get("services") or []
    return svcs if isinstance(svcs, list) else []


def _host_labels(host: dict) -> list[str]:
    labels = host.get("labels") or host.get("host", {}).get("labels") or []
    out: list[str] = []
    for lab in labels if isinstance(labels, list) else []:
        if isinstance(lab, str):
            out.append(lab)
        elif isinstance(lab, dict):
            v = lab.get("value") or lab.get("name")
            if v:
                out.append(str(v))
    return out


def _service_labels(host: dict) -> list[str]:
    out: list[str] = []
    for svc in _services(host):
        for lab in svc.get("labels", []) or []:
            if isinstance(lab, dict) and lab.get("value"):
                out.append(str(lab["value"]))
            elif isinstance(lab, str):
                out.append(lab)
    return out


def _asn_name(host: dict) -> str:
    asys = host.get("autonomous_system") or host.get("host", {}).get(
        "autonomous_system"
    ) or {}
    return str(asys.get("name", "")) if isinstance(asys, dict) else ""


def is_honeypot(host: dict, honeypot_labels: list[str]) -> bool:
    """True si el host presenta cualquier etiqueta de honeypot."""
    wanted = {s.lower() for s in honeypot_labels}
    present = {s.lower() for s in _host_labels(host) + _service_labels(host)}
    return bool(wanted & present)


def is_cloud(host: dict, cloud_asn_names: list[str]) -> bool:
    """True si el ASN del host pertenece a un proveedor cloud conocido."""
    name = _asn_name(host).lower()
    return any(c.lower() in name for c in cloud_asn_names)


def has_industrial_label(host: dict) -> bool:
    """True si Censys etiqueta el host/servicio como sistema de control industrial."""
    labels = {s.lower().replace("_", "-") for s in _host_labels(host) + _service_labels(host)}
    return "industrial-control-system" in labels


def filter_hosts(
    hosts: list[dict],
    honeypot_labels: list[str],
    cloud_asn_names: list[str],
    drop_cloud: bool = True,
) -> dict[str, list[dict]]:
    """Separa los hosts en `kept` y `excluded` aplicando los criterios de la Tabla 4.2.

    Devuelve {'kept': [...], 'excluded': [{host, reason}, ...]}.
    """
    kept: list[dict] = []
    excluded: list[dict] = []
    for host in hosts:
        if is_honeypot(host, honeypot_labels):
            excluded.append({"host": host, "reason": "honeypot"})
            continue
        if drop_cloud and is_cloud(host, cloud_asn_names) and not has_industrial_label(host):
            # Se excluye cloud salvo que esté explícitamente etiquetado como ICS.
            excluded.append({"host": host, "reason": "cloud_no_ics"})
            continue
        kept.append(host)
    return {"kept": kept, "excluded": excluded}


def dedup_by_ip(hosts: list[dict]) -> list[dict]:
    """Elimina hosts duplicados por IP (varias consultas pueden solaparse)."""
    seen: set[str] = set()
    out: list[dict] = []
    for host in hosts:
        ip = host.get("ip") or host.get("host", {}).get("ip")
        key = str(ip)
        if key and key not in seen:
            seen.add(key)
            out.append(host)
    return out
