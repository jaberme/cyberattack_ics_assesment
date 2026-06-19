"""Fase 5a — Extracción del *fingerprint* de cada host.

A partir de los metadatos que Censys asocia a cada servicio (software, CPE,
protocolo, puerto), construye una lista de huellas digitales por host. Estas
huellas alimentan después la correlación manual con NVD/CISA (módulo
`cve_correlation`).

No requiere conexión al sistema: trabaja exclusivamente sobre el registro
indexado por Censys.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any


# Mapa puerto -> protocolo ICS conocido (Tabla 2.2 del TFG). Sirve de respaldo
# cuando Censys no etiqueta el protocolo explícitamente.
PORT_PROTOCOL = {
    102: "S7Comm",
    502: "Modbus TCP",
    1217: "CODESYS",
    2404: "IEC-104",
    4840: "OPC UA",
    5900: "VNC",
    20000: "DNP3",
    20256: "Unitronics PCOM",
    23: "Telnet",
    3389: "RDP",
    34964: "PROFINET-CM",
    44818: "EtherNet/IP",
    47808: "BACnet/IP",
}


@dataclass
class Fingerprint:
    """Huella digital de un servicio expuesto."""

    port: int | None
    protocol: str | None
    vendor: str | None
    product: str | None
    version: str | None
    cpe: str | None

    def keyword(self) -> str:
        """Cadena de búsqueda por palabras clave para NVD (vendor + product)."""
        parts = [p for p in (self.vendor, self.product, self.version) if p]
        return " ".join(parts).strip()

    def to_dict(self) -> dict:
        return asdict(self)


def _services(host: dict) -> list[dict]:
    svcs = host.get("services") or host.get("host", {}).get("services") or []
    return svcs if isinstance(svcs, list) else []


def _extract_software(svc: dict) -> list[dict]:
    sw = svc.get("software")
    if isinstance(sw, list):
        return [s for s in sw if isinstance(s, dict)]
    if isinstance(sw, dict):
        return [sw]
    return []


def _first_cpe(entry: dict) -> str | None:
    # Distintas versiones usan 'cpe', 'uniform_resource_identifier' o una lista.
    for key in ("cpe", "uniform_resource_identifier", "cpe23", "uri"):
        val = entry.get(key)
        if isinstance(val, str) and val.startswith("cpe:"):
            return val
        if isinstance(val, list):
            for v in val:
                if isinstance(v, str) and v.startswith("cpe:"):
                    return v
    return None


def extract_fingerprints(host: dict) -> list[Fingerprint]:
    """Devuelve la lista de fingerprints (deduplicada) de un host."""
    out: dict[tuple, Fingerprint] = {}
    for svc in _services(host):
        port = svc.get("port")
        protocol = (
            svc.get("protocol")
            or svc.get("service_name")
            or svc.get("extended_service_name")
            or PORT_PROTOCOL.get(port)
        )
        software = _extract_software(svc)
        if not software:
            fp = Fingerprint(port, protocol, None, None, None, None)
            out[(port, protocol, None, None, None)] = fp
            continue
        for sw in software:
            vendor = sw.get("vendor") or sw.get("manufacturer")
            product = sw.get("product") or sw.get("name")
            version = sw.get("version")
            cpe = _first_cpe(sw)
            fp = Fingerprint(port, protocol, vendor, product, version, cpe)
            out[(port, protocol, vendor, product, version)] = fp
    return list(out.values())


def host_ip(host: dict) -> str | None:
    return host.get("ip") or host.get("host", {}).get("ip")


def host_country(host: dict) -> str | None:
    loc = host.get("location") or host.get("host", {}).get("location") or {}
    return loc.get("country_code") if isinstance(loc, dict) else None


def host_ports(host: dict) -> set[int]:
    return {svc.get("port") for svc in _services(host) if isinstance(svc.get("port"), int)}
