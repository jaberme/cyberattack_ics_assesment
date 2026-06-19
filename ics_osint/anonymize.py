"""Fase 7 — Anonimización (Sección 3.1.3 del TFG).

Aplica el principio de anonimización antes de persistir o reportar cualquier
dato: las direcciones IP se truncan o pseudonimizan y, opcionalmente, se omiten
los nombres de organización/ASN cuando su divulgación pudiera permitir localizar
un sistema vulnerable.

La anonimización se aplica POR DEFECTO en las salidas del módulo `report`, de
modo que el documento final nunca contenga IPs completas ni credenciales.
"""

from __future__ import annotations

import hashlib
import ipaddress


def truncate_ip(ip: str, keep_octets: int = 2) -> str:
    """Trunca una IPv4/IPv6 conservando solo los primeros `keep_octets` grupos.

    Ejemplos:
        truncate_ip("93.51.120.7", 2) -> "93.51.x.x"
        truncate_ip("2001:db8::1", 2) -> "2001:db8:x:x:x:x:x:x"
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "x.x.x.x"
    if addr.version == 4:
        parts = ip.split(".")
        kept = parts[:keep_octets]
        return ".".join(kept + ["x"] * (4 - len(kept)))
    parts = addr.exploded.split(":")
    kept = parts[:keep_octets]
    return ":".join(kept + ["x"] * (8 - len(kept)))


def pseudonymize_ip(ip: str, salt: str = "") -> str:
    """Devuelve un pseudónimo estable (hash con sal) en lugar de la IP real.

    Permite correlacionar el mismo host entre consultas sin revelar la IP.
    """
    digest = hashlib.sha256((salt + str(ip)).encode("utf-8")).hexdigest()
    return f"host-{digest[:10]}"


def anonymize_ip(ip: str, method: str = "truncate", keep_octets: int = 2, salt: str = "") -> str:
    if not ip:
        return ""
    if method == "hash":
        return pseudonymize_ip(ip, salt)
    return truncate_ip(ip, keep_octets)


def anonymize_record(
    record: dict,
    method: str = "truncate",
    keep_octets: int = 2,
    salt: str = "",
    omit_org: bool = True,
) -> dict:
    """Devuelve una COPIA del registro de hallazgo con la IP anonimizada.

    `record` es la salida de `cve_correlation.analyze_host`.
    Si `omit_org` es True, no se incluye ningún nombre de organización/ASN.
    """
    out = dict(record)
    if "ip" in out and out["ip"]:
        out["ip"] = anonymize_ip(out["ip"], method, keep_octets, salt)
    if omit_org:
        out.pop("autonomous_system", None)
        out.pop("organization", None)
    return out
